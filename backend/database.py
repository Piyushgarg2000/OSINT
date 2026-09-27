import os
import time
from datetime import datetime
from decimal import Decimal
from dotenv import load_dotenv
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

# Load .env file automatically from backend or root directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))
load_dotenv(os.path.join(os.path.dirname(BASE_DIR), ".env"))

AWS_REGION            = os.getenv("AWS_REGION", "us-east-1")
AWS_ACCESS_KEY_ID     = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
TABLE_NAME            = os.getenv("DYNAMO_TABLE_NAME", "osint_ip_cache")

_dynamodb     = None
_table        = None
_is_available = False


# ── Type conversion helpers ───────────────────────────────────────────────────
# DynamoDB does not accept Python float; every number must be Decimal.
# These helpers recursively convert dicts/lists so data round-trips cleanly.

def _to_dynamo(obj):
    """Recursively convert Python types to DynamoDB-safe types (float/int -> Decimal)."""
    if obj is None:
        return None
    if isinstance(obj, bool):
        return obj                        # bool must come before int (bool is a subclass of int)
    if isinstance(obj, float):
        return Decimal(str(obj))          # str() avoids floating-point precision drift
    if isinstance(obj, int):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: _to_dynamo(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_to_dynamo(i) for i in obj if i is not None]
    return obj


def _from_dynamo(obj):
    """Recursively convert DynamoDB types back to native Python types (Decimal -> int/float)."""
    if isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    if isinstance(obj, dict):
        return {k: _from_dynamo(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_from_dynamo(i) for i in obj]
    return obj


# ── Table bootstrap ───────────────────────────────────────────────────────────

def _ensure_table(dynamodb):
    """Return the DynamoDB Table resource, auto-creating the table if it does not exist yet."""
    client = dynamodb.meta.client
    try:
        client.describe_table(TableName=TABLE_NAME)
        print(f"[DynamoDB] Table '{TABLE_NAME}' found.")
        return dynamodb.Table(TABLE_NAME)
    except client.exceptions.ResourceNotFoundException:
        pass

    print(f"[DynamoDB] Table '{TABLE_NAME}' not found — creating...")
    table = dynamodb.create_table(
        TableName=TABLE_NAME,
        KeySchema=[
            {"AttributeName": "ip", "KeyType": "HASH"},   # Partition key = IP string
        ],
        AttributeDefinitions=[
            {"AttributeName": "ip", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",   # On-demand pricing; no provisioning required
    )
    table.wait_until_exists()
    print(f"[DynamoDB] Table '{TABLE_NAME}' created successfully.")
    return table


def get_table():
    """Return a live DynamoDB Table resource (lazy singleton, replaces old get_db())."""
    global _dynamodb, _table, _is_available
    if _table is not None and _is_available:
        return _table

    try:
        kwargs = {"region_name": AWS_REGION}
        if AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY:
            kwargs["aws_access_key_id"]     = AWS_ACCESS_KEY_ID
            kwargs["aws_secret_access_key"] = AWS_SECRET_ACCESS_KEY

        _dynamodb     = boto3.resource("dynamodb", **kwargs)
        _table        = _ensure_table(_dynamodb)
        _is_available = True
        print(f"[DynamoDB] Connected successfully. Table: {TABLE_NAME}")
        return _table
    except (NoCredentialsError, Exception) as e:
        _is_available = False
        print(f"[DynamoDB] Connection notice: {e}")
        return None


# ── Public interface — IDENTICAL signatures to original MongoDB database.py ───
# main.py imports exactly these 6 names and they work unchanged.

def is_db_connected() -> bool:
    """Lightweight liveness check — mirrors old is_db_connected()."""
    table = get_table()
    if table is None:
        return False
    try:
        table.meta.client.describe_table(TableName=TABLE_NAME)
        return True
    except Exception:
        return False


def get_cached_search(ip: str):
    """
    Fetch cached IP search results.
    Mirrors: db.ip_cache.find_one({"ip": ip}) -> doc["search_results"]
    """
    table = get_table()
    if table is None:
        return None
    try:
        resp = table.get_item(Key={"ip": ip})
        item = resp.get("Item")
        if item and "search_results" in item:
            data = _from_dynamo(item["search_results"])
            data["_from_cache"] = True
            data["_cached_at"]  = item.get("updated_at_str", "")
            return data
    except Exception:
        pass
    return None


def save_cached_search(ip: str, search_results: dict):
    """
    Upsert search results + atomically increment scan_count.
    Mirrors: db.ip_cache.update_one({ip}, {$set: ..., $inc: {scan_count:1}}, upsert=True)

    DynamoDB equivalent:
      SET  search_results, updated_at_str, updated_at_epoch
      ADD  scan_count  (atomic increment; initialises to 0 if attribute is missing)
    """
    table = get_table()
    if table is None:
        return
    try:
        now_str   = datetime.now().strftime("%d %b %Y, %H:%M:%S")
        now_epoch = Decimal(str(time.time()))   # Unix timestamp used for sort in get_recent_scanned_ips

        clean = dict(search_results)
        clean.pop("_from_cache", None)
        clean.pop("_cached_at",  None)

        table.update_item(
            Key={"ip": ip},
            UpdateExpression=(
                "SET search_results  = :sr, "
                "    updated_at_str  = :ts, "
                "    updated_at_epoch = :ep "
                "ADD scan_count :inc"
            ),
            ExpressionAttributeValues={
                ":sr":  _to_dynamo(clean),
                ":ts":  now_str,
                ":ep":  now_epoch,
                ":inc": Decimal("1"),
            },
        )
        country = (
            clean.get("geography", {}).get("geolite2") or
            clean.get("bgp_info", {}).get("country") or
            "Global"
        )
        org = clean.get("bgp_info", {}).get("org") or ""
        _record_recent_scan(ip, now_str, country, org, table)

        # Real-time incremental ASN intelligence update
        try:
            from asn_analytics import record_scanned_ip_asn
            record_scanned_ip_asn(clean, table)
        except Exception:
            pass
    except Exception as e:
        print(f"Notice: DynamoDB save search warning: {e}")


def get_cached_audit(ip: str):
    """
    Fetch cached VPN/infrastructure audit results.
    Mirrors: db.ip_cache.find_one({"ip": ip}) -> doc["audit_results"]
    """
    table = get_table()
    if table is None:
        return None
    try:
        resp = table.get_item(Key={"ip": ip})
        item = resp.get("Item")
        if item and "audit_results" in item:
            data = _from_dynamo(item["audit_results"])
            data["_from_cache"] = True
            data["_cached_at"]  = item.get("updated_at_str", "")
            return data
    except Exception:
        pass
    return None


def save_cached_audit(ip: str, audit_results: dict):
    """
    Upsert audit results + atomically increment audit_count.
    Mirrors: db.ip_cache.update_one({ip}, {$set: ..., $inc: {audit_count:1}}, upsert=True)
    """
    table = get_table()
    if table is None:
        return
    try:
        now_str   = datetime.now().strftime("%d %b %Y, %H:%M:%S")
        now_epoch = Decimal(str(time.time()))

        clean = dict(audit_results)
        clean.pop("_from_cache", None)
        clean.pop("_cached_at",  None)

        table.update_item(
            Key={"ip": ip},
            UpdateExpression=(
                "SET audit_results   = :ar, "
                "    updated_at_str  = :ts, "
                "    updated_at_epoch = :ep "
                "ADD audit_count :inc"
            ),
            ExpressionAttributeValues={
                ":ar":  _to_dynamo(clean),
                ":ts":  now_str,
                ":ep":  now_epoch,
                ":inc": Decimal("1"),
            },
        )

        country = clean.get("detected_country") or clean.get("bgp_info", {}).get("country") or "Global"
        org = clean.get("bgp_info", {}).get("org") or ""
        _record_recent_scan(ip, now_str, country, org, table)

        # Real-time incremental ASN intelligence update
        try:
            from asn_analytics import record_scanned_ip_asn
            record_scanned_ip_asn(clean, table)
        except Exception:
            pass
    except Exception as e:
        print(f"Notice: DynamoDB save audit warning: {e}")


# ── Recent scans fast-caching & bounded lookups ──────────────────────────────
_recent_scans_cache = []

def _record_recent_scan(ip: str, cached_at: str, country: str, org: str, table=None):
    """Update in-memory recent scans buffer and persist metadata to DynamoDB."""
    global _recent_scans_cache
    if not ip or ip.startswith("__"):
        return
    entry = {
        "ip": ip,
        "cached_at": cached_at,
        "country": country or "Global",
        "org": org or "",
    }
    _recent_scans_cache = [entry] + [x for x in _recent_scans_cache if x.get("ip") != ip][:19]
    if table is not None:
        try:
            table.put_item(
                Item={
                    "ip": "__recent_scans_meta__",
                    "recent_scans": _to_dynamo(_recent_scans_cache),
                    "updated_at_str": cached_at,
                    "updated_at_epoch": Decimal(str(time.time())),
                }
            )
        except Exception:
            pass


def get_recent_scanned_ips(limit: int = 10):
    """
    Return the most-recently scanned IPs (newest first), up to `limit`.
    Uses in-memory cache and single-item metadata record to avoid slow full-table scans.
    """
    global _recent_scans_cache
    if _recent_scans_cache:
        return _recent_scans_cache[:limit]

    table = get_table()
    if table is None:
        return []

    # 1. Fast metadata point-lookup (O(1) in ~20ms)
    try:
        meta_resp = table.get_item(Key={"ip": "__recent_scans_meta__"})
        item = meta_resp.get("Item")
        if item and "recent_scans" in item:
            _recent_scans_cache = _from_dynamo(item["recent_scans"])
            if _recent_scans_cache:
                return _recent_scans_cache[:limit]
    except Exception:
        pass

    # 2. Cold bootstrap: Bounded single-page scan (Limit=30, never loops all 50k items)
    try:
        resp = table.scan(
            Limit=30,
            ProjectionExpression=(
                "ip, updated_at_str, updated_at_epoch, "
                "search_results, audit_results"
            )
        )
        items = [i for i in resp.get("Items", []) if not str(i.get("ip", "")).startswith("__")]
        items.sort(
            key=lambda x: float(x.get("updated_at_epoch", 0)),
            reverse=True,
        )
        results = []
        for item in items:
            ip = item.get("ip")
            search_res = _from_dynamo(item.get("search_results", {}))
            audit_res = _from_dynamo(item.get("audit_results", {}))

            country = (
                audit_res.get("detected_country") or
                search_res.get("bgp_info", {}).get("country") or
                search_res.get("geography", {}).get("geolite2") or
                "Global"
            )
            org = (
                search_res.get("bgp_info", {}).get("org") or
                audit_res.get("bgp_info", {}).get("org") or
                ""
            )
            results.append({
                "ip": ip,
                "cached_at": item.get("updated_at_str", ""),
                "country": country,
                "org": org,
            })
        _recent_scans_cache = results
        # Persist so future calls use O(1) point lookup
        try:
            table.put_item(
                Item={
                    "ip": "__recent_scans_meta__",
                    "recent_scans": _to_dynamo(_recent_scans_cache),
                    "updated_at_str": datetime.now().strftime("%d %b %Y, %H:%M:%S"),
                    "updated_at_epoch": Decimal(str(time.time())),
                }
            )
        except Exception:
            pass
        return _recent_scans_cache[:limit]
    except Exception:
        return []
