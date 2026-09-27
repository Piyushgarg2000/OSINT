"""
asn_analytics.py
----------------
Pre-computes ASN / Hosting-Provider threat intelligence from scanned IP data
already stored in DynamoDB.

Aggregation output is stored as a single fast-lookup DynamoDB item:
  pk = "__asn_analytics_meta__"

Calling build_asn_threat_intelligence() is safe to call at any time and
will NOT touch any real IP records.  It only reads them and writes a single
metadata document.

Public API
----------
  build_asn_threat_intelligence() -> dict | None
  get_asn_threat_intelligence()   -> dict | None   (fast O(1) cache read)
"""

import os
import json
import time
import threading
from collections import defaultdict
from decimal import Decimal
from typing import Optional

from database import get_table, _to_dynamo, _from_dynamo

LOCAL_CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "asn_analytics_cache.json")

# ── Internal state ────────────────────────────────────────────────────────────
_analytics_cache: Optional[dict] = None
_cache_last_fetched: float = 0.0
_analytics_lock = threading.Lock()
CACHE_TTL_SECONDS = 20.0  # Check DynamoDB every 20s if background workers ingested new data

# ── Infrastructure type normaliser ────────────────────────────────────────────
INFRA_LABELS = {
    "DATACENTER": "DATACENTER",
    "ANYCAST":    "ANYCAST_CDN",
    "RESIDENTIAL": "RESIDENTIAL",
    "ENTERPRISE":  "RESIDENTIAL",
    "UNKNOWN":     "RESIDENTIAL",
}

def _normalise_infra(infra_type: str) -> str:
    t = (infra_type or "").upper()
    if "ANYCAST" in t or "CDN" in t:
        return "ANYCAST_CDN"
    if "DATACENTER" in t or "VPN" in t or "HOSTING" in t:
        return "DATACENTER"
    return "RESIDENTIAL"


# ── Core aggregation ──────────────────────────────────────────────────────────

# ── Guard to prevent concurrent builds ───────────────────────────────────────
_is_building = False

# ── Core aggregation ──────────────────────────────────────────────────────────

def build_asn_threat_intelligence():
    """
    Bounded parallel DynamoDB scan aggregated by ASN.
    - Uses 4 parallel scan segments to distribute table read load
    - Caps at MAX_ITEMS_PER_SEGMENT items per segment (fast, statistically valid)
    - Guards against concurrent execution
    - Writes result as single O(1) DynamoDB item; fast frontend reads
    """
    global _analytics_cache, _is_building
    with _analytics_lock:
        if _is_building:
            print("[ASN-Analytics] Build already in progress, skipping.")
            return None
        _is_building = True

    table = get_table()
    if table is None:
        with _analytics_lock:
            _is_building = False
        return None

    print("[ASN-Analytics] Starting full parallel aggregation scan across all DynamoDB records …")
    t0 = time.time()

    # ── Full parallel scan: 8 segments, scanning entire table without arbitrary caps ──
    TOTAL_SEGMENTS = 8
    all_items = []

    def _scan_segment(seg_idx):
        seg_items = []
        kwargs = {"Segment": seg_idx, "TotalSegments": TOTAL_SEGMENTS}
        while True:
            resp = table.scan(**kwargs)
            for i in resp.get("Items", []):
                ip_val = str(i.get("ip", ""))
                if not ip_val.startswith("__") and "search_results" in i:
                    seg_items.append(i)
            if "LastEvaluatedKey" not in resp:
                break
            kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
        return seg_items

    # Run all 8 segments in parallel threads
    seg_results = [[] for _ in range(TOTAL_SEGMENTS)]
    threads = []
    for seg in range(TOTAL_SEGMENTS):
        def _worker(s=seg):
            seg_results[s] = _scan_segment(s)
        t = threading.Thread(target=_worker)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    for seg_list in seg_results:
        all_items.extend(seg_list)

    print(f"[ASN-Analytics] Loaded {len(all_items)} total IP records in {time.time()-t0:.1f}s.")

    if not all_items:
        print("[ASN-Analytics] No scanned IP data yet – skipping aggregation.")
        with _analytics_lock:
            _is_building = False
        return None

    # ── Aggregation ───────────────────────────────────────────────────────────
    asn_data = {}
    infra_counts = defaultdict(int)
    total_classified = 0
    global_total_threats = 0

    for item in all_items:
        sr = _from_dynamo(item.get("search_results", {}))
        if not sr:
            continue

        bgp              = sr.get("bgp_info", {})
        behavioral_flags = sr.get("behavioral_flags", [])

        if isinstance(behavioral_flags, list) and len(behavioral_flags) > 0:
            global_total_threats += 1

        asn      = bgp.get("asn", "")
        org      = bgp.get("org", "Unknown")
        country  = bgp.get("country", "Unknown")
        infra_raw = bgp.get("infra_type", "RESIDENTIAL / ENTERPRISE ISP")

        if not asn or asn == "Unknown" or not isinstance(behavioral_flags, list):
            continue

        infra_key = _normalise_infra(infra_raw)

        if asn not in asn_data:
            asn_data[asn] = {
                "asn":        asn,
                "org":        org,
                "country":    country,
                "infra_type": infra_raw,
                "infra_key":  infra_key,
                "total_ips":  0,
                "categories": defaultdict(int),
            }

        entry = asn_data[asn]
        entry["total_ips"] += 1

        if org not in ("Unknown", "BGP Lookup Unavailable", ""):
            entry["org"]     = org
            entry["country"] = country

        for flag in behavioral_flags:
            if isinstance(flag, str):
                entry["categories"][flag] += 1

        infra_counts[infra_key] += 1
        total_classified += 1

    # ── Build ranked lists ────────────────────────────────────────────────────
    results_list = []
    for asn, d in asn_data.items():
        total = d["total_ips"]
        cats  = dict(d["categories"])
        pcts  = {c: round((n / total) * 100, 1) for c, n in cats.items() if total > 0}
        primary = max(cats, key=cats.get) if cats else "clean"

        results_list.append({
            "asn":                  asn,
            "org":                  d["org"],
            "country":              d["country"],
            "infra_type":           d["infra_type"],
            "infra_key":            d["infra_key"],
            "total_threat_ips":     total,
            "category_counts":      cats,
            "category_percentages": pcts,
            "primary_threat":       primary,
        })

    results_list.sort(key=lambda x: x["total_threat_ips"], reverse=True)

    worst_asns    = results_list[:25]
    dirty_hosters = [x for x in results_list if x["infra_key"] == "DATACENTER"][:10]

    infra_distribution = {}
    for key, count in infra_counts.items():
        pct = round((count / total_classified) * 100, 1) if total_classified > 0 else 0.0
        infra_distribution[key] = {"count": count, "percentage": pct}

    # ── Approximate total table item count (fast metadata call, no scan) ──────
    total_table_items = 0
    try:
        desc = table.meta.client.describe_table(TableName=table.name)
        total_table_items = int(desc.get("Table", {}).get("ItemCount", 0))
    except Exception as e:
        print(f"[ASN-Analytics] Warning: describe_table failed: {e}")

    payload = {
        "updated_at":         time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_table_items":  total_table_items,
        "global_total_threats": global_total_threats,
        "total_analyzed_ips": total_classified,
        "sample_size":        len(all_items),
        "total_asns":         len(results_list),
        "worst_asns":         worst_asns,
        "dirty_hosters":      dirty_hosters,
        "all_asns":           results_list,
        "infra_distribution": infra_distribution,
    }

    # ── Persist to DynamoDB ───────────────────────────────────────────────────
    try:
        table.put_item(Item={
            "ip":         "__asn_analytics_meta__",
            "analytics":  _to_dynamo(payload),
            "updated_at": payload["updated_at"],
        })
    except Exception as exc:
        print(f"[ASN-Analytics] Warning: Could not persist to DynamoDB: {exc}")

    # ── Persist to Local JSON File (Instant Offline / Restart Cache) ─────────
    try:
        with open(LOCAL_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"[ASN-Analytics] Saved persistent snapshot to {LOCAL_CACHE_FILE}")
    except Exception as exc:
        print(f"[ASN-Analytics] Warning: Could not write local cache file: {exc}")

    elapsed = time.time() - t0
    print(f"[ASN-Analytics] Done in {elapsed:.1f}s — "
          f"{len(results_list)} ASNs from {total_classified} classified IPs "
          f"(total scanned: {len(all_items)}).")

    with _analytics_lock:
        _analytics_cache = payload
        _cache_last_fetched = time.time()
        _is_building = False

    return payload


def get_asn_threat_intelligence() -> Optional[dict]:
    """
    Fast O(1) read with multi-tier caching:
    1. In-memory cache (<0.1ms)
    2. Local JSON disk cache (~1ms)
    3. DynamoDB point lookup (__asn_analytics_meta__) (~20ms)
    """
    global _analytics_cache, _cache_last_fetched

    now = time.time()
    with _analytics_lock:
        if _analytics_cache is not None and (now - _cache_last_fetched) < CACHE_TTL_SECONDS:
            return _analytics_cache

    # Tier 2: Check local disk cache
    if os.path.exists(LOCAL_CACHE_FILE):
        try:
            with open(LOCAL_CACHE_FILE, "r", encoding="utf-8") as f:
                disk_data = json.load(f)
            if disk_data and "worst_asns" in disk_data:
                with _analytics_lock:
                    _analytics_cache = disk_data
                    _cache_last_fetched = now
                return disk_data
        except Exception as exc:
            print(f"[ASN-Analytics] Disk cache read note: {exc}")

    # Tier 3: DynamoDB point lookup
    table = get_table()
    if table is None:
        return _analytics_cache

    try:
        resp = table.get_item(Key={"ip": "__asn_analytics_meta__"})
        item = resp.get("Item")
        if item and "analytics" in item:
            data = _from_dynamo(item["analytics"])
            with _analytics_lock:
                _analytics_cache = data
                _cache_last_fetched = now
            # Write through to local disk for subsequent instant loads
            try:
                with open(LOCAL_CACHE_FILE, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            except Exception:
                pass
            return data
    except Exception as exc:
        print(f"[ASN-Analytics] DynamoDB read warning: {exc}")

    return _analytics_cache


def record_scanned_ip_asn(search_results: dict, table=None):
    """
    Real-time incremental updater.
    Triggered automatically whenever a new IP is scanned and stored in DynamoDB.
    Updates the ASN intelligence model instantly without requiring any table scan.
    """
    if not isinstance(search_results, dict):
        return

    bgp = search_results.get("bgp_info", {})
    asn = bgp.get("asn", "")
    flags = search_results.get("behavioral_flags", [])

    if not asn or asn in ("Unknown", "BGP Lookup Unavailable") or not isinstance(flags, list):
        return

    global _analytics_cache
    cache = get_asn_threat_intelligence()
    if not cache:
        return

    with _analytics_lock:
        try:
            # 1. Increment total analyzed
            cache["total_analyzed_ips"] = cache.get("total_analyzed_ips", 0) + 1
            if "total_table_items" in cache and cache["total_table_items"]:
                cache["total_table_items"] += 1

            # 2. Update infra distribution
            infra_raw = bgp.get("infra_type", "RESIDENTIAL / ENTERPRISE ISP")
            infra_key = _normalise_infra(infra_raw)
            infra_dist = cache.get("infra_distribution", {})
            if infra_key not in infra_dist:
                infra_dist[infra_key] = {"count": 0, "percentage": 0.0}
            infra_dist[infra_key]["count"] += 1

            total_classified = cache["total_analyzed_ips"]
            for k in infra_dist:
                cnt = infra_dist[k].get("count", 0)
                infra_dist[k]["percentage"] = round((cnt / total_classified) * 100, 1) if total_classified > 0 else 0.0

            # 3. Update or insert ASN into worst_asns / dirty_hosters list
            org = bgp.get("org", "Unknown")
            country = bgp.get("country", "Unknown")

            worst_asns = cache.get("worst_asns", [])
            target = next((x for x in worst_asns if x.get("asn") == asn), None)

            if target:
                target["total_threat_ips"] = target.get("total_threat_ips", 0) + 1
                cat_counts = target.get("category_counts", {})
                for f in flags:
                    if isinstance(f, str):
                        cat_counts[f] = cat_counts.get(f, 0) + 1
                target["category_counts"] = cat_counts
                tot = target["total_threat_ips"]
                target["category_percentages"] = {
                    c: round((n / tot) * 100, 1) for c, n in cat_counts.items() if tot > 0
                }
                target["primary_threat"] = max(cat_counts, key=cat_counts.get) if cat_counts else "clean"
                if org not in ("Unknown", "BGP Lookup Unavailable", ""):
                    target["org"] = org
                    target["country"] = country
            else:
                cat_counts = {}
                for f in flags:
                    if isinstance(f, str):
                        cat_counts[f] = 1
                tot = 1
                pcts = {c: 100.0 for c in cat_counts}
                primary = max(cat_counts, key=cat_counts.get) if cat_counts else "clean"
                new_entry = {
                    "asn": asn,
                    "org": org,
                    "country": country,
                    "infra_type": infra_raw,
                    "infra_key": infra_key,
                    "total_threat_ips": tot,
                    "category_counts": cat_counts,
                    "category_percentages": pcts,
                    "primary_threat": primary,
                }
                worst_asns.append(new_entry)

            worst_asns.sort(key=lambda x: x.get("total_threat_ips", 0), reverse=True)
            cache["worst_asns"] = worst_asns[:25]
            cache["total_asns"] = len(worst_asns)

            # Update dirty hosters if DATACENTER
            all_hosters = [x for x in worst_asns if x.get("infra_key") == "DATACENTER"]
            cache["dirty_hosters"] = all_hosters[:10]
            cache["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

            _analytics_cache = cache
            _cache_last_fetched = time.time()
        except Exception as e:
            print(f"[ASN-Analytics] Incremental update error: {e}")
            return

    # Asynchronously persist updated cache to DynamoDB point item
    def _async_persist():
        try:
            tb = table or get_table()
            if tb is not None:
                tb.put_item(Item={
                    "ip": "__asn_analytics_meta__",
                    "analytics": _to_dynamo(_analytics_cache),
                    "updated_at": _analytics_cache.get("updated_at", ""),
                })
        except Exception as err:
            print(f"[ASN-Analytics] Async persist warning: {err}")

    threading.Thread(target=_async_persist, daemon=True).start()

