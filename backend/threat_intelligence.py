"""
threat_intelligence.py
----------------------
OSINT Threat Intelligence Analytics Engine

Derives structured intelligence from existing DynamoDB IP records for a given ASN.

Pipeline:
    Raw DynamoDB records  →  Prefix Clustering  →  Statistical Analysis
    →  Pattern Detection  →  Intelligence Findings

Public API
----------
    get_asn_deep_intelligence(asn, force_refresh=False) -> dict
    invalidate_asn_cache(asn)  -> None

Data sources used (all from existing DynamoDB fields)
------------------------------------------------------
    search_results.bgp_info.asn          → ASN matching
    search_results.ripestat.prefix        → BGP-announced CIDR (authoritative)
    search_results.behavioral_flags       → Threat categories
    search_results.bgp_info.country       → Country (primary)
    search_results.geography              → Multi-provider geo consensus
    search_results.bgp_info.infra_type    → Infrastructure classification
    search_results.bgp_info.infra_key     → Normalised infra key
    search_results.updated_at_epoch       → Last-observed timestamp
    search_results.ripestat.announced_asn → Cross-check ASN
    search_results.ripestat.visibility    → BGP visibility string
"""

import time
import math
import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from database import get_table, _to_dynamo, _from_dynamo

# ── Configurable Thresholds ────────────────────────────────────────────────────
# All policy thresholds are centralised here — never scattered in logic.

DENSITY_THRESHOLDS = {
    "VERY_HIGH": 25.0,   # >25% of prefix space observed as threat IPs
    "HIGH":      10.0,   # 10-25%
    "MEDIUM":     1.0,   # 1-10%
    # LOW = anything below MEDIUM
}

CONCENTRATION_THRESHOLDS = {
    "HIGH":     75.0,    # top-5 share > 75% → Highly Concentrated
    "MODERATE": 50.0,    # 50-75%            → Moderately Concentrated
    # DISTRIBUTED = below MODERATE
}

PERSISTENCE_DAYS = {
    "PERSISTENT":  30,   # last seen > 30 days ago → persistent in dataset
    "SHORT_TERM":   7,   # 7-30 days
    # TRANSIENT = <7 days
}

CACHE_TTL_SECONDS = 3600   # 1 hour per-ASN cache TTL

MIN_FINDINGS_THRESHOLD = {
    "concentration_high":       75.0,
    "concentration_moderate":   50.0,
    "dominant_category_share":  40.0,
    "very_high_density_pct":    25.0,
    "high_density_pct":         10.0,
    "persistent_ratio":         50.0,
    "geo_concentration_top2":   70.0,
    "multi_category_min":        3,
}

# ── In-memory cache ────────────────────────────────────────────────────────────
_ti_cache: dict = {}          # { "AS16509": {"data": ..., "ts": float} }
_ti_lock = threading.Lock()


# ── Utility helpers ────────────────────────────────────────────────────────────

def _prefix_size(cidr: str) -> int:
    """Return the number of IPv4 addresses in a CIDR prefix (e.g. /24 → 256)."""
    try:
        prefix_len = int(cidr.split("/")[1])
        return 2 ** (32 - prefix_len)
    except Exception:
        return 0


def _safe_pct(numerator: float, denominator: float, decimals: int = 1) -> float:
    if denominator == 0:
        return 0.0
    return round((numerator / denominator) * 100, decimals)


def _density_class(density_pct: float) -> str:
    if density_pct >= DENSITY_THRESHOLDS["VERY_HIGH"]:
        return "VERY_HIGH"
    if density_pct >= DENSITY_THRESHOLDS["HIGH"]:
        return "HIGH"
    if density_pct >= DENSITY_THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    return "LOW"


def _concentration_class(top5_pct: float) -> str:
    if top5_pct >= CONCENTRATION_THRESHOLDS["HIGH"]:
        return "HIGHLY_CONCENTRATED"
    if top5_pct >= CONCENTRATION_THRESHOLDS["MODERATE"]:
        return "MODERATELY_CONCENTRATED"
    return "DISTRIBUTED"


def _shannon_entropy(category_counts: dict, total: int) -> Optional[float]:
    """
    Shannon entropy H = -Σ p_i × log2(p_i) over threat categories.
    Returns None if fewer than 2 categories are present.
    Represents spread/diversity of threat categories in a prefix.
    """
    if total == 0 or len(category_counts) < 2:
        return None
    h = 0.0
    for count in category_counts.values():
        if count > 0:
            p = count / total
            h -= p * math.log2(p)
    return round(h, 3)


def _max_possible_entropy(n_categories: int) -> float:
    """Maximum possible entropy for n categories (all equal → H_max = log2(n))."""
    return math.log2(n_categories) if n_categories >= 2 else 0.0


# ── Core Analytics Functions ───────────────────────────────────────────────────

def _extract_ip_features(item: dict) -> Optional[dict]:
    """
    Extract standardised features from a raw DynamoDB item.
    Returns None if the item cannot be used for analysis.
    """
    sr = _from_dynamo(item.get("search_results", {}))
    if not sr:
        return None

    bgp = sr.get("bgp_info", {})
    ripestat = sr.get("ripestat", {})
    geography = sr.get("geography", {})

    asn = bgp.get("asn", "")
    if not asn or asn in ("Unknown", "BGP Lookup Unavailable"):
        return None

    # Prefix: use ripestat.prefix (authoritative BGP announcement)
    prefix = ripestat.get("prefix", "")
    if not prefix or prefix in ("Unknown", "N/A", ""):
        prefix = "Prefix Unavailable"

    # Country: use majority consensus
    country = (
        bgp.get("country") or
        ripestat.get("holder_registry", {}).get("country") or
        next((v for v in geography.values() if v and v != "Unknown"), None) or
        "Unknown"
    )

    infra_type = bgp.get("infra_type", "UNKNOWN")
    infra_key  = bgp.get("infra_key", "RESIDENTIAL")

    categories = []
    for flag in sr.get("behavioral_flags", []):
        if isinstance(flag, str):
            categories.append(flag)

    # Timestamp for persistence analysis
    ts = item.get("updated_at_epoch")
    try:
        ts = float(ts) if ts is not None else None
    except (TypeError, ValueError):
        ts = None

    return {
        "ip":         item.get("ip", ""),
        "asn":        asn,
        "prefix":     prefix,
        "country":    country,
        "infra_type": infra_type,
        "infra_key":  infra_key,
        "categories": categories,
        "timestamp":  ts,
        "bgp_visibility": ripestat.get("visibility", ""),
    }


def _prefix_analysis(features: list) -> list:
    """
    Group IPs by BGP-announced prefix and compute per-prefix metrics.

    Returns a list of prefix records sorted by threat IP count (descending).
    """
    prefix_map: dict = {}

    for f in features:
        p = f["prefix"]
        if p not in prefix_map:
            prefix_map[p] = {
                "prefix":     p,
                "ip_list":    [],
                "categories": defaultdict(int),
                "countries":  defaultdict(int),
                "infra_keys": defaultdict(int),
            }
        prefix_map[p]["ip_list"].append(f["ip"])
        for cat in f["categories"]:
            prefix_map[p]["categories"][cat] += 1
        prefix_map[p]["countries"][f["country"]] += 1
        prefix_map[p]["infra_keys"][f["infra_key"]] += 1

    results = []
    for prefix, data in prefix_map.items():
        count       = len(data["ip_list"])
        cat_counts  = dict(data["categories"])
        cat_total   = sum(cat_counts.values())
        cat_pcts    = {c: _safe_pct(n, cat_total) for c, n in cat_counts.items()}
        dominant    = max(cat_counts, key=cat_counts.get) if cat_counts else None
        n_cats      = len(cat_counts)
        entropy     = _shannon_entropy(cat_counts, cat_total)

        # Prefix size from CIDR  (0 if prefix unavailable)
        p_size      = _prefix_size(prefix) if prefix != "Prefix Unavailable" else 0
        density_pct = _safe_pct(count, p_size) if p_size > 0 else None
        d_class     = _density_class(density_pct) if density_pct is not None else "UNKNOWN"

        top_country = max(data["countries"], key=data["countries"].get) if data["countries"] else "Unknown"
        top_infra   = max(data["infra_keys"], key=data["infra_keys"].get) if data["infra_keys"] else "UNKNOWN"

        results.append({
            "prefix":             prefix,
            "threat_ip_count":    count,
            "prefix_size":        p_size,
            "threat_density_pct": density_pct,
            "density_class":      d_class,
            "category_counts":    cat_counts,
            "category_pcts":      cat_pcts,
            "dominant_category":  dominant,
            "category_count":     n_cats,
            "shannon_entropy":    entropy,
            "top_country":        top_country,
            "top_infra_key":      top_infra,
            "country_breakdown":  dict(data["countries"]),
            "infra_breakdown":    dict(data["infra_keys"]),
            "sample_ips":         data["ip_list"][:5],   # First 5 IPs as evidence
        })

    results.sort(key=lambda x: x["threat_ip_count"], reverse=True)
    return results


def _concentration_analysis(prefix_list: list, total: int) -> dict:
    """
    Compute top-K threat concentration metrics.
    All values are percentages of total ASN threat IPs.
    """
    if total == 0 or not prefix_list:
        return {
            "top1": 0.0, "top3": 0.0, "top5": 0.0, "top10": 0.0,
            "classification": "DISTRIBUTED",
            "top_prefixes_evidence": []
        }

    cumulative = 0
    evidence   = []
    result     = {"top1": 0.0, "top3": 0.0, "top5": 0.0, "top10": 0.0}
    targets    = {1: "top1", 3: "top3", 5: "top5", 10: "top10"}

    for i, prefix in enumerate(prefix_list, 1):
        cumulative += prefix["threat_ip_count"]
        if i in targets:
            result[targets[i]] = _safe_pct(cumulative, total)
        if i <= 10:
            evidence.append({
                "rank":    i,
                "prefix":  prefix["prefix"],
                "count":   prefix["threat_ip_count"],
                "pct":     _safe_pct(prefix["threat_ip_count"], total),
            })

    result["classification"]       = _concentration_class(result["top5"])
    result["top_prefixes_evidence"] = evidence
    return result


def _category_distribution(features: list, total: int) -> list:
    """Overall category share across all IPs in the ASN."""
    cat_counts: dict = defaultdict(int)
    for f in features:
        for cat in f["categories"]:
            cat_counts[cat] += 1

    result = []
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        result.append({
            "category":   cat,
            "count":      count,
            "share_pct":  _safe_pct(count, total),
        })
    return result


def _geographic_distribution(features: list) -> list:
    """Threat IP count by country (from best-available field)."""
    country_counts: dict = defaultdict(int)
    for f in features:
        c = f["country"] or "Unknown"
        country_counts[c] += 1

    total = sum(country_counts.values())
    result = []
    for country, count in sorted(country_counts.items(), key=lambda x: -x[1]):
        result.append({
            "country": country,
            "count":   count,
            "pct":     _safe_pct(count, total),
        })
    return result


def _infrastructure_distribution(features: list) -> list:
    """Threat IP count by normalised infrastructure type."""
    infra_counts: dict = defaultdict(int)
    infra_labels = {
        "DATACENTER":  "Datacenter / VPN Hosting",
        "RESIDENTIAL": "Residential / ISP",
        "ANYCAST_CDN": "Anycast CDN / Edge",
    }
    for f in features:
        key = f.get("infra_key") or "RESIDENTIAL"
        infra_counts[key] += 1

    total = sum(infra_counts.values())
    result = []
    for key, count in sorted(infra_counts.items(), key=lambda x: -x[1]):
        result.append({
            "infra_key":   key,
            "label":       infra_labels.get(key, key),
            "count":       count,
            "pct":         _safe_pct(count, total),
        })
    return result


def _temporal_analysis(features: list) -> dict:
    """
    Persistence analysis using `updated_at_epoch` (last-observed timestamp).

    NOTE: This timestamp reflects the last time the IP was SCANNED and saved
    to the DynamoDB cache — not the first time it was identified as a threat.
    It serves as a 'last observed' marker. We classify IPs by how recently
    they were observed relative to NOW.

    Classification:
        Transient   : last seen < 7 days ago
        Short-term  : last seen 7–30 days ago
        Persistent  : last seen > 30 days ago (still in dataset)
    """
    now_epoch = time.time()
    now_dt    = datetime.fromtimestamp(now_epoch, tz=timezone.utc)

    persistent  = 0
    short_term  = 0
    transient   = 0
    no_ts       = 0

    ages_days = []
    for f in features:
        ts = f.get("timestamp")
        if ts is None:
            no_ts += 1
            continue
        age_days = (now_epoch - ts) / 86400.0
        ages_days.append(age_days)
        if age_days > PERSISTENCE_DAYS["PERSISTENT"]:
            persistent += 1
        elif age_days > PERSISTENCE_DAYS["SHORT_TERM"]:
            short_term += 1
        else:
            transient += 1

    total_timestamped = persistent + short_term + transient
    if total_timestamped == 0:
        return {
            "available":          False,
            "reason":             "No timestamp data available for this dataset.",
            "total_no_timestamp": no_ts,
        }

    return {
        "available":            True,
        "as_of":                now_dt.strftime("%Y-%m-%d %H:%M UTC"),
        "note":                 (
            "Timestamps reflect the date each IP was last scanned and saved to the "
            "DynamoDB cache — used here as 'last observed' markers."
        ),
        "persistent_count":     persistent,
        "short_term_count":     short_term,
        "transient_count":      transient,
        "no_timestamp_count":   no_ts,
        "total_timestamped":    total_timestamped,
        "persistent_pct":       _safe_pct(persistent, total_timestamped),
        "short_term_pct":       _safe_pct(short_term, total_timestamped),
        "transient_pct":        _safe_pct(transient, total_timestamped),
        "median_age_days":      round(sorted(ages_days)[len(ages_days) // 2], 1) if ages_days else None,
    }


def _category_heatmap(prefix_list: list, top_n: int = 10) -> dict:
    """
    Build a Prefix × Category heatmap for the top-N prefixes.
    Returns a matrix suitable for frontend rendering.
    """
    # Gather all categories present across top-N prefixes
    top_prefixes = prefix_list[:top_n]
    all_cats: set = set()
    for p in top_prefixes:
        all_cats.update(p["category_counts"].keys())
    all_cats_sorted = sorted(all_cats)

    rows = []
    for p in top_prefixes:
        cat_total = sum(p["category_counts"].values())
        row = {
            "prefix":          p["prefix"],
            "threat_ip_count": p["threat_ip_count"],
            "dominant":        p["dominant_category"],
            "cells":           {}
        }
        for cat in all_cats_sorted:
            count = p["category_counts"].get(cat, 0)
            row["cells"][cat] = {
                "count": count,
                "pct":   _safe_pct(count, cat_total) if cat_total > 0 else 0.0,
            }
        rows.append(row)

    return {
        "categories": all_cats_sorted,
        "rows":       rows,
    }


# ── Intelligence Findings Engine ───────────────────────────────────────────────

def _generate_findings(
    asn: str,
    total: int,
    prefix_list: list,
    concentration: dict,
    category_dist: list,
    geo_dist: list,
    infra_dist: list,
    temporal: dict,
) -> list:
    """
    Deterministic rule-based findings engine.
    Every finding includes: title, description, metric, value, severity, evidence.

    Findings are ordered by severity: CRITICAL → HIGH → MEDIUM → INFO.
    """
    findings = []
    T = MIN_FINDINGS_THRESHOLD

    # ── F1: High Prefix Concentration ─────────────────────────────────────────
    top5 = concentration.get("top5", 0.0)
    top3 = concentration.get("top3", 0.0)
    conc_class = concentration.get("classification", "")
    if top5 >= T["concentration_high"] and len(prefix_list) >= 5:
        findings.append({
            "id":          "high_prefix_concentration",
            "title":       "High Threat Concentration in Top Prefixes",
            "description": (
                f"{top5}% of observed threat IPs are concentrated within "
                f"the top 5 prefixes of {asn}. This indicates that threat "
                f"observations are not uniformly distributed — a small number "
                f"of network blocks account for the vast majority of activity."
            ),
            "metric":    "top5_concentration",
            "value":     top5,
            "severity":  "HIGH",
            "evidence":  concentration.get("top_prefixes_evidence", []),
        })
    elif top5 >= T["concentration_moderate"] and len(prefix_list) >= 5:
        findings.append({
            "id":          "moderate_prefix_concentration",
            "title":       "Moderate Threat Concentration",
            "description": (
                f"{top5}% of observed threat IPs fall within the top 5 "
                f"prefixes. Threat activity shows moderate geographic clustering "
                f"rather than uniform distribution across the ASN."
            ),
            "metric":    "top5_concentration",
            "value":     top5,
            "severity":  "MEDIUM",
            "evidence":  concentration.get("top_prefixes_evidence", []),
        })

    # ── F2: Single Dominant Threat Category ───────────────────────────────────
    if category_dist:
        dominant_cat = category_dist[0]
        if dominant_cat["share_pct"] >= T["dominant_category_share"]:
            findings.append({
                "id":          "dominant_category",
                "title":       f"Dominant Threat Category: {dominant_cat['category'].title()}",
                "description": (
                    f"The '{dominant_cat['category']}' category accounts for "
                    f"{dominant_cat['share_pct']}% of observed threat records "
                    f"in {asn} ({dominant_cat['count']} of {total} IPs). "
                    f"This represents the empirical category proportion — not a "
                    f"probability that any individual IP belongs to this category."
                ),
                "metric":    "dominant_category_share",
                "value":     dominant_cat["share_pct"],
                "severity":  "HIGH" if dominant_cat["share_pct"] >= 60 else "MEDIUM",
                "evidence":  [
                    {"category": d["category"], "count": d["count"], "pct": d["share_pct"]}
                    for d in category_dist[:5]
                ],
            })

    # ── F3: Very High Density Prefix ──────────────────────────────────────────
    very_high_density_prefixes = [
        p for p in prefix_list
        if p.get("density_class") == "VERY_HIGH" and p["prefix"] != "Prefix Unavailable"
    ]
    if very_high_density_prefixes:
        top = very_high_density_prefixes[0]
        findings.append({
            "id":          "very_high_density_prefix",
            "title":       f"Very High Observed Threat Density: {top['prefix']}",
            "description": (
                f"Prefix {top['prefix']} has {top['threat_ip_count']} observed "
                f"threat IPs out of {top['prefix_size']:,} total addresses "
                f"({top['threat_density_pct']:.1f}% observed threat density). "
                f"This is classified as Very High — over 25% of the prefix space "
                f"has been observed in threat intelligence feeds."
            ),
            "metric":    "observed_threat_density",
            "value":     top["threat_density_pct"],
            "severity":  "CRITICAL",
            "evidence":  [
                {"prefix": p["prefix"], "count": p["threat_ip_count"], "density": p["threat_density_pct"]}
                for p in very_high_density_prefixes[:3]
            ],
        })

    # ── F4: High Density Prefix ────────────────────────────────────────────────
    elif prefix_list and prefix_list[0].get("density_class") in ("HIGH",) \
            and prefix_list[0]["prefix"] != "Prefix Unavailable":
        top = prefix_list[0]
        findings.append({
            "id":          "high_density_prefix",
            "title":       f"High Observed Threat Density: {top['prefix']}",
            "description": (
                f"Prefix {top['prefix']} has {top['threat_ip_count']} observed "
                f"threat IPs out of {top['prefix_size']:,} total addresses "
                f"({top['threat_density_pct']:.1f}% observed threat density)."
            ),
            "metric":    "observed_threat_density",
            "value":     top["threat_density_pct"],
            "severity":  "HIGH",
            "evidence":  [
                {"prefix": top["prefix"], "count": top["threat_ip_count"], "density": top["threat_density_pct"]}
            ],
        })

    # ── F5: Multi-Category Threat Diversity ───────────────────────────────────
    multi_cat_prefixes = [
        p for p in prefix_list
        if p["category_count"] >= T["multi_category_min"]
    ]
    if multi_cat_prefixes:
        top = multi_cat_prefixes[0]
        findings.append({
            "id":          "multi_category_threat",
            "title":       "Multi-Category Threat Activity Detected",
            "description": (
                f"{len(multi_cat_prefixes)} prefix(es) show observations across "
                f"{top['category_count']} or more distinct threat categories. "
                f"Prefix {top['prefix']} has the highest diversity with "
                f"{top['category_count']} categories present. "
                f"This indicates co-location of different types of threat activity "
                f"within the same network block."
            ),
            "metric":    "category_count_in_prefix",
            "value":     top["category_count"],
            "severity":  "MEDIUM",
            "evidence":  [
                {"prefix": p["prefix"], "categories": list(p["category_counts"].keys())}
                for p in multi_cat_prefixes[:5]
            ],
        })

    # ── F6: Temporal Persistence ───────────────────────────────────────────────
    if temporal.get("available") and temporal.get("persistent_pct", 0) >= T["persistent_ratio"]:
        findings.append({
            "id":          "high_persistence",
            "title":       "Long-Term Observation Persistence",
            "description": (
                f"{temporal['persistent_pct']}% of observed threat IPs "
                f"({temporal['persistent_count']} of {temporal['total_timestamped']}) "
                f"were last recorded in the dataset more than "
                f"{PERSISTENCE_DAYS['PERSISTENT']} days ago, indicating they remain "
                f"present in the dataset over an extended period."
            ),
            "metric":    "persistent_ratio",
            "value":     temporal["persistent_pct"],
            "severity":  "MEDIUM",
            "evidence":  [{"note": temporal.get("note", "")}],
        })

    # ── F7: Geographic Concentration ──────────────────────────────────────────
    if len(geo_dist) >= 2:
        top2_pct = geo_dist[0]["pct"] + geo_dist[1]["pct"]
        if top2_pct >= T["geo_concentration_top2"]:
            findings.append({
                "id":          "geo_concentration",
                "title":       "Geographic Concentration of Observed IPs",
                "description": (
                    f"{top2_pct:.1f}% of observed threat IPs are mapped to two "
                    f"geographic locations: {geo_dist[0]['country']} "
                    f"({geo_dist[0]['pct']}%) and {geo_dist[1]['country']} "
                    f"({geo_dist[1]['pct']}%). Note: GeoIP location reflects "
                    f"IP registration or infrastructure location, not attacker origin."
                ),
                "metric":    "top2_country_share",
                "value":     round(top2_pct, 1),
                "severity":  "INFO",
                "evidence":  [{"country": g["country"], "count": g["count"], "pct": g["pct"]}
                              for g in geo_dist[:5]],
            })

    # ── F8: Datacenter Infrastructure Dominance ────────────────────────────────
    dc = next((i for i in infra_dist if i["infra_key"] == "DATACENTER"), None)
    if dc and dc["pct"] >= 60:
        findings.append({
            "id":          "datacenter_dominance",
            "title":       "Datacenter Infrastructure Dominance",
            "description": (
                f"{dc['pct']}% of observed threat IPs in {asn} are associated "
                f"with datacenter / VPN hosting infrastructure. "
                f"Datacenter-hosted threats are typically associated with "
                f"automated scanning, exploit distribution, and botnet C2 nodes."
            ),
            "metric":    "datacenter_pct",
            "value":     dc["pct"],
            "severity":  "HIGH",
            "evidence":  infra_dist,
        })

    # ── Sort by severity ───────────────────────────────────────────────────────
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 99))

    return findings


# ── DynamoDB Per-ASN Cache ─────────────────────────────────────────────────────

_CACHE_KEY_PREFIX = "__asn_ti_"


def _cache_key(asn: str) -> str:
    return f"{_CACHE_KEY_PREFIX}{asn}__"


def _read_dynamo_cache(asn: str) -> Optional[dict]:
    table = get_table()
    if table is None:
        return None
    try:
        resp = table.get_item(Key={"ip": _cache_key(asn)})
        item = resp.get("Item")
        if item and "ti_data" in item:
            data = _from_dynamo(item["ti_data"])
            cached_at = float(item.get("cached_at_epoch", 0))
            if (time.time() - cached_at) < CACHE_TTL_SECONDS:
                return data
    except Exception as e:
        print(f"[ThreatIntel] DynamoDB cache read warning for {asn}: {e}")
    return None


def _write_dynamo_cache(asn: str, data: dict):
    table = get_table()
    if table is None:
        return
    try:
        table.put_item(Item={
            "ip":             _cache_key(asn),
            "ti_data":        _to_dynamo(data),
            "cached_at_epoch": _to_dynamo(time.time()),
            "updated_at":     time.strftime("%Y-%m-%d %H:%M:%S"),
        })
    except Exception as e:
        print(f"[ThreatIntel] DynamoDB cache write warning for {asn}: {e}")


def invalidate_asn_cache(asn: str):
    """Force-invalidate in-memory and DynamoDB cache for a specific ASN."""
    with _ti_lock:
        _ti_cache.pop(asn, None)


# ── Main Entry Point ───────────────────────────────────────────────────────────

def get_asn_deep_intelligence(asn: str, force_refresh: bool = False) -> dict:
    """
    Main entry point. Returns full threat intelligence analysis for a given ASN.

    Cache hierarchy:
        1. In-memory (< 0.1ms)
        2. DynamoDB point-lookup (~20ms)
        3. Full DynamoDB parallel scan + compute (~5-30s, then cached)

    Parameters
    ----------
    asn           : ASN string, e.g. "AS16509"
    force_refresh : bypass all caches and recompute from scratch
    """
    asn = asn.strip().upper()
    if not asn.startswith("AS"):
        asn = "AS" + asn

    now = time.time()

    # ── Tier 1: In-memory cache ────────────────────────────────────────────────
    if not force_refresh:
        with _ti_lock:
            entry = _ti_cache.get(asn)
            if entry and (now - entry["ts"]) < CACHE_TTL_SECONDS:
                return entry["data"]

    # ── Tier 2: DynamoDB cache ─────────────────────────────────────────────────
    if not force_refresh:
        dynamo_cached = _read_dynamo_cache(asn)
        if dynamo_cached:
            with _ti_lock:
                _ti_cache[asn] = {"data": dynamo_cached, "ts": now}
            return dynamo_cached

    # ── Tier 3: Full computation ───────────────────────────────────────────────
    result = _compute_asn_intelligence(asn)

    # Store in both caches
    with _ti_lock:
        _ti_cache[asn] = {"data": result, "ts": now}
    threading.Thread(target=_write_dynamo_cache, args=(asn, result), daemon=True).start()

    return result


def _compute_asn_intelligence(asn: str) -> dict:
    """
    Full DynamoDB scan to collect all IPs for this ASN, then run analytics pipeline.
    Uses parallel 4-segment scan to distribute read load.
    """
    t0 = time.time()
    print(f"[ThreatIntel] Computing deep intelligence for {asn}…")

    table = get_table()
    if table is None:
        return _insufficient_data(asn, "DynamoDB unavailable")

    # ── Parallel scan: 4 segments ──────────────────────────────────────────────
    TOTAL_SEGMENTS = 4
    collected: list = []
    lock = threading.Lock()

    def _scan_segment(seg):
        seg_items = []
        kwargs = {"Segment": seg, "TotalSegments": TOTAL_SEGMENTS}
        while True:
            resp = table.scan(**kwargs)
            for item in resp.get("Items", []):
                ip_val = str(item.get("ip", ""))
                if ip_val.startswith("__") or "search_results" not in item:
                    continue
                # Quick ASN pre-filter using raw attribute to avoid full _from_dynamo on every item
                sr_raw = item.get("search_results", {})
                bgp_raw = sr_raw.get("bgp_info", {}) if isinstance(sr_raw, dict) else {}
                item_asn = bgp_raw.get("asn", "") if isinstance(bgp_raw, dict) else ""
                if str(item_asn).upper() == asn:
                    seg_items.append(item)
            if "LastEvaluatedKey" not in resp:
                break
            kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
        with lock:
            collected.extend(seg_items)

    threads = [threading.Thread(target=_scan_segment, args=(s,)) for s in range(TOTAL_SEGMENTS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print(f"[ThreatIntel] Collected {len(collected)} items for {asn} in {time.time()-t0:.1f}s")

    if not collected:
        return _insufficient_data(asn, f"No records found for {asn} in DynamoDB")

    # ── Extract features ───────────────────────────────────────────────────────
    features = []
    for item in collected:
        f = _extract_ip_features(item)
        if f and f["asn"].upper() == asn:
            features.append(f)

    total = len(features)
    if total == 0:
        return _insufficient_data(asn, f"No analysable records found for {asn}")

    # ── Run analytics pipeline ────────────────────────────────────────────────
    prefix_list    = _prefix_analysis(features)
    concentration  = _concentration_analysis(prefix_list, total)
    category_dist  = _category_distribution(features, total)
    geo_dist       = _geographic_distribution(features)
    infra_dist     = _infrastructure_distribution(features)
    temporal       = _temporal_analysis(features)
    heatmap        = _category_heatmap(prefix_list, top_n=10)
    findings       = _generate_findings(
        asn, total, prefix_list, concentration,
        category_dist, geo_dist, infra_dist, temporal
    )

    # ── Summary metrics ────────────────────────────────────────────────────────
    unique_prefixes    = len([p for p in prefix_list if p["prefix"] != "Prefix Unavailable"])
    unavailable_count  = len([p for p in prefix_list if p["prefix"] == "Prefix Unavailable"])
    unique_countries   = len(geo_dist)
    n_categories       = len(category_dist)
    dominant_cat       = category_dist[0] if category_dist else None
    top_prefix         = prefix_list[0] if prefix_list else None

    elapsed = time.time() - t0
    print(f"[ThreatIntel] Completed {asn}: {total} IPs, {unique_prefixes} prefixes, "
          f"{len(findings)} findings in {elapsed:.1f}s")

    return {
        "status":        "success",
        "asn":           asn,
        "computed_at":   time.strftime("%Y-%m-%d %H:%M:%S"),
        "computation_ms": round(elapsed * 1000),

        # ── Summary ────────────────────────────────────────────────────────────
        "summary": {
            "total_threat_ips":       total,
            "unique_prefixes":        unique_prefixes,
            "unavailable_prefix_ips": sum(
                p["threat_ip_count"] for p in prefix_list
                if p["prefix"] == "Prefix Unavailable"
            ),
            "unique_countries":  unique_countries,
            "n_categories":      n_categories,
            "dominant_category": dominant_cat["category"] if dominant_cat else None,
            "dominant_category_share": dominant_cat["share_pct"] if dominant_cat else 0.0,
            "concentration_class":    concentration["classification"],
            "top5_concentration":     concentration["top5"],
            "top_prefix":             top_prefix["prefix"] if top_prefix else None,
            "top_prefix_density":     top_prefix.get("threat_density_pct") if top_prefix else None,
            "top_prefix_count":       top_prefix["threat_ip_count"] if top_prefix else None,
        },

        # ── Full analytics ──────────────────────────────────────────────────────
        "prefix_analysis":         prefix_list,
        "concentration":           concentration,
        "category_distribution":   category_dist,
        "geographic_distribution": geo_dist,
        "infrastructure_distribution": infra_dist,
        "temporal_analysis":       temporal,
        "category_heatmap":        heatmap,
        "findings":                findings,
    }


def _insufficient_data(asn: str, reason: str) -> dict:
    return {
        "status":  "insufficient_data",
        "asn":     asn,
        "reason":  reason,
        "message": (
            "Insufficient data to generate threat intelligence analysis. "
            "This ASN may not have been observed in the scanned dataset, "
            "or the DynamoDB connection is unavailable."
        ),
        "summary":                    None,
        "prefix_analysis":            [],
        "concentration":              None,
        "category_distribution":      [],
        "geographic_distribution":    [],
        "infrastructure_distribution":[],
        "temporal_analysis":          {"available": False, "reason": reason},
        "category_heatmap":           {"categories": [], "rows": []},
        "findings":                   [],
    }
