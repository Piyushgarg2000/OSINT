"""
ml_threat_model.py — OSINT Threat Intelligence ML Engine
=========================================================
Trains a RandomForestClassifier on all DynamoDB IP records and provides
per-IP threat probability predictions with explainable risk factors.

Feature set (all 100% available in real DynamoDB data):
  1. asn_number        — integer extracted from ripestat.announced_asn
  2. prefix_length     — CIDR length extracted from ripestat.prefix
  3. bgp_visibility    — BGP visibility % from ripestat.visibility
  4. geo_consensus     — number of GeoIP providers that agree on country
  5. is_anycast        — boolean from bgp_info.is_anycast
  6. asn_threat_rate   — target-encoded: historical threat % for this ASN
  7. country_threat_rate — target-encoded: historical threat % for this country

Label: binary — 1 if behavioral_flags non-empty, 0 otherwise
"""

import os
import re
import json
import time
import math
import pickle
import logging
import threading
import collections
from decimal import Decimal
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple

import boto3
from boto3.dynamodb.conditions import Attr

logger = logging.getLogger("ml_threat_model")

# ── Constants ────────────────────────────────────────────────────────────────

CATEGORIES = ["abuse", "anonymizers", "attacks", "malware",
              "organizations", "reputation", "spam", "unroutable"]

MODEL_CACHE_PATH = os.path.join(os.path.dirname(__file__), "threat_model_v1.pkl")
MODEL_MAX_AGE_S  = 24 * 3600   # retrain after 24 hours
MIN_SAMPLES_TRAIN = 200         # minimum records to attempt training

DYNAMO_TABLE  = os.environ.get("DYNAMO_TABLE_NAME", "researchProject01")
DYNAMO_REGION = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "eu-north-1"))

# Risk thresholds
RISK_THRESHOLDS = {
    "CRITICAL": 0.80,
    "HIGH":     0.60,
    "MEDIUM":   0.40,
    "LOW":      0.0,
}
RISK_COLORS = {
    "CRITICAL": "#EF4444",
    "HIGH":     "#F97316",
    "MEDIUM":   "#F59E0B",
    "LOW":      "#10B981",
}

# ── Module-level state (thread-safe via lock) ────────────────────────────────

_state_lock   = threading.Lock()
_model        = None      # sklearn model
_meta         = None      # dict: training metadata
_asn_rates    = {}        # ASN → threat rate (float)
_country_rates= {}        # country → threat rate (float)
_global_rate  = 0.12      # fallback when ASN/country unseen
_training_in_progress = False


# ── Feature engineering helpers ───────────────────────────────────────────────

def _parse_asn_number(asn_str: str) -> int:
    """'AS200373' → 200373. Unknown/None → 0."""
    if not asn_str:
        return 0
    m = re.search(r"(\d+)", str(asn_str))
    return int(m.group(1)) if m else 0


def _parse_prefix_length(prefix_str: str) -> int:
    """'45.3.42.0/24' → 24. Unknown/None → 24 (default)."""
    if not prefix_str or prefix_str == "Unknown":
        return 24
    m = re.search(r"/(\d+)$", str(prefix_str))
    return int(m.group(1)) if m else 24


def _parse_visibility(vis_str: str) -> float:
    """'99.7% (326/327 RIS Peers)' → 99.7. None/Unknown → 0.0."""
    if not vis_str:
        return 0.0
    m = re.search(r"([\d.]+)%", str(vis_str))
    return float(m.group(1)) if m else 0.0


def _geo_consensus(geo_dict: dict) -> Tuple[int, str]:
    """Return (consensus_count, consensus_country). Max 4 providers."""
    if not geo_dict:
        return 0, "Unknown"
    counts = collections.Counter(
        v for v in geo_dict.values() if v and v not in ("Unknown", "N/A", "")
    )
    if not counts:
        return 0, "Unknown"
    top_country, top_count = counts.most_common(1)[0]
    return top_count, top_country


def _from_dynamo_val(v):
    """Recursively convert Decimal → float/int."""
    if isinstance(v, Decimal):
        f = float(v)
        return int(f) if f.is_integer() else f
    if isinstance(v, dict):
        return {k: _from_dynamo_val(vv) for k, vv in v.items()}
    if isinstance(v, list):
        return [_from_dynamo_val(i) for i in v]
    return v


def _extract_record_features(item: dict) -> Optional[dict]:
    """
    Extract feature dict from a raw DynamoDB item.
    Returns None if the record is a metadata item or has no search_results.
    """
    ip = str(item.get("ip", ""))
    if ip.startswith("__") or not ip:
        return None

    sr = item.get("search_results") or {}
    if not sr:
        return None

    bgp   = sr.get("bgp_info") or {}
    ripe  = sr.get("ripestat")  or {}
    geo   = sr.get("geography") or {}
    flags = sr.get("behavioral_flags") or []

    asn_str    = ripe.get("announced_asn") or bgp.get("asn") or ""
    prefix_str = ripe.get("prefix", "")
    vis_str    = ripe.get("visibility", "")
    is_anycast = 1 if bgp.get("is_anycast") else 0

    geo_count, country = _geo_consensus(geo)

    label         = 1 if flags else 0
    categories    = [f for f in flags if f in CATEGORIES]

    return {
        "ip":             ip,
        "asn_str":        asn_str,
        "asn_number":     _parse_asn_number(asn_str),
        "prefix_length":  _parse_prefix_length(prefix_str),
        "bgp_visibility": _parse_visibility(vis_str),
        "geo_consensus":  geo_count,
        "is_anycast":     is_anycast,
        "country":        country,
        "label":          label,
        "categories":     categories,
    }


# ── DynamoDB scan ─────────────────────────────────────────────────────────────

def _scan_all_records() -> List[dict]:
    """Parallel 4-segment full scan of DynamoDB. Returns list of feature dicts."""
    dyn   = boto3.resource("dynamodb", region_name=DYNAMO_REGION)
    table = dyn.Table(DYNAMO_TABLE)

    records = []
    errors  = []

    def scan_segment(seg: int, total: int, out: list):
        try:
            kwargs = {
                "TotalSegments": total,
                "Segment": seg,
                "ProjectionExpression": "ip, search_results",
            }
            while True:
                resp  = table.scan(**kwargs)
                items = resp.get("Items", [])
                for item in items:
                    feat = _extract_record_features(_from_dynamo_val(item))
                    if feat:
                        out.append(feat)
                if "LastEvaluatedKey" not in resp:
                    break
                kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
        except Exception as exc:
            errors.append(str(exc))

    threads = []
    parts   = [[] for _ in range(4)]
    for seg in range(4):
        t = threading.Thread(target=scan_segment, args=(seg, 4, parts[seg]))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    for part in parts:
        records.extend(part)

    if errors:
        logger.warning("Scan errors: %s", errors)

    logger.info("Scanned %d IP records from DynamoDB", len(records))
    return records


# ── Training ─────────────────────────────────────────────────────────────────

def _build_target_encodings(records: List[dict]):
    """Compute per-ASN and per-country threat rates from training data."""
    asn_totals     = collections.defaultdict(lambda: [0, 0])   # [threats, total]
    country_totals = collections.defaultdict(lambda: [0, 0])

    for r in records:
        asn_totals[r["asn_str"]][1]     += 1
        asn_totals[r["asn_str"]][0]     += r["label"]
        country_totals[r["country"]][1] += 1
        country_totals[r["country"]][0] += r["label"]

    global_threat = sum(r["label"] for r in records)
    global_total  = len(records)
    global_rate   = global_threat / global_total if global_total > 0 else 0.12

    # Smoothed rates (Laplace smoothing, alpha=5)
    alpha = 5.0
    asn_rates = {}
    for asn, (threats, total) in asn_totals.items():
        asn_rates[asn] = (threats + alpha * global_rate) / (total + alpha)

    country_rates = {}
    for country, (threats, total) in country_totals.items():
        country_rates[country] = (threats + alpha * global_rate) / (total + alpha)

    return asn_rates, country_rates, global_rate


def _to_feature_matrix(records: List[dict], asn_rates: dict, country_rates: dict, global_rate: float):
    """Convert records list → (X numpy array, y numpy array)."""
    import numpy as np
    X = np.zeros((len(records), 7), dtype=np.float32)
    y = np.zeros(len(records), dtype=np.int32)

    for i, r in enumerate(records):
        X[i, 0] = r["asn_number"]
        X[i, 1] = r["prefix_length"]
        X[i, 2] = r["bgp_visibility"]
        X[i, 3] = r["geo_consensus"]
        X[i, 4] = r["is_anycast"]
        X[i, 5] = asn_rates.get(r["asn_str"], global_rate)
        X[i, 6] = country_rates.get(r["country"], global_rate)
        y[i]    = r["label"]

    return X, y


FEATURE_NAMES = [
    "ASN Number",
    "Prefix Length",
    "BGP Visibility %",
    "GeoIP Consensus",
    "Is Anycast",
    "ASN Historical Threat Rate",
    "Country Historical Threat Rate",
]


def train_model(force: bool = False) -> dict:
    """
    Train and persist the RandomForest model.
    Returns dict with training results.
    Thread-safe — skips if training already in progress.
    """
    global _model, _meta, _asn_rates, _country_rates, _global_rate, _training_in_progress

    with _state_lock:
        if _training_in_progress:
            return {"status": "already_training"}
        _training_in_progress = True

    try:
        t0 = time.time()
        logger.info("Starting ML model training...")

        # Load from cache if fresh enough
        if not force and os.path.exists(MODEL_CACHE_PATH):
            age = time.time() - os.path.getmtime(MODEL_CACHE_PATH)
            if age < MODEL_MAX_AGE_S:
                loaded = _load_model_from_disk()
                if loaded:
                    logger.info("Loaded model from cache (age %.0fh)", age / 3600)
                    return {"status": "loaded_from_cache", **loaded["meta"]}

        # Scan DynamoDB
        records = _scan_all_records()
        if len(records) < MIN_SAMPLES_TRAIN:
            return {"status": "insufficient_data", "n_records": len(records)}

        # Build encodings
        asn_rates, country_rates, global_rate = _build_target_encodings(records)

        # Feature matrix
        X, y = _to_feature_matrix(records, asn_rates, country_rates, global_rate)

        # Train-test split
        from sklearn.model_selection import train_test_split
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import classification_report, roc_auc_score

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.20, random_state=42, stratify=y
        )

        clf = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            min_samples_leaf=10,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        clf.fit(X_train, y_train)

        # Evaluate
        y_pred  = clf.predict(X_test)
        y_prob  = clf.predict_proba(X_test)[:, 1]
        report  = classification_report(y_test, y_pred, output_dict=True)
        auc     = float(roc_auc_score(y_test, y_prob))

        n_threats = int(y.sum())
        n_total   = len(y)

        # Feature importance
        importances = [
            {"feature": FEATURE_NAMES[i], "importance": round(float(v), 4)}
            for i, v in enumerate(clf.feature_importances_)
        ]
        importances.sort(key=lambda x: x["importance"], reverse=True)

        meta = {
            "status":             "trained",
            "trained_at":         datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            "training_seconds":   round(time.time() - t0, 1),
            "n_records":          n_total,
            "n_threats":          n_threats,
            "n_clean":            n_total - n_threats,
            "threat_rate_pct":    round(n_threats / n_total * 100, 1),
            "test_accuracy":      round(report["accuracy"], 4),
            "test_auc_roc":       round(auc, 4),
            "precision_threat":   round(report.get("1", {}).get("precision", 0), 4),
            "recall_threat":      round(report.get("1", {}).get("recall", 0), 4),
            "f1_threat":          round(report.get("1", {}).get("f1-score", 0), 4),
            "feature_importances": importances,
            "features_used":       FEATURE_NAMES,
            "model_type":         "RandomForestClassifier (200 trees, balanced weights)",
            "global_threat_rate": round(global_rate, 4),
        }

        # Build per-category threat rates from training data
        cat_rates = {}
        for cat in CATEGORIES:
            cat_ips  = [r for r in records if cat in r["categories"]]
            cat_rates[cat] = round(len(cat_ips) / n_total * 100, 2) if n_total > 0 else 0

        payload = {
            "model":         clf,
            "meta":          meta,
            "asn_rates":     asn_rates,
            "country_rates": country_rates,
            "global_rate":   global_rate,
            "cat_rates":     cat_rates,
        }

        # Persist
        with open(MODEL_CACHE_PATH, "wb") as f:
            pickle.dump(payload, f)

        with _state_lock:
            _model         = clf
            _meta          = meta
            _asn_rates     = asn_rates
            _country_rates = country_rates
            _global_rate   = global_rate

        logger.info("Training complete: accuracy=%.3f AUC=%.3f n=%d",
                    meta["test_accuracy"], auc, n_total)
        return meta

    except Exception as exc:
        logger.exception("Training failed: %s", exc)
        return {"status": "error", "error": str(exc)}
    finally:
        with _state_lock:
            _training_in_progress = False


def _load_model_from_disk() -> Optional[dict]:
    """Load pickled model from disk into module state. Returns payload dict or None."""
    global _model, _meta, _asn_rates, _country_rates, _global_rate
    try:
        with open(MODEL_CACHE_PATH, "rb") as f:
            payload = pickle.load(f)
        with _state_lock:
            _model         = payload["model"]
            _meta          = payload["meta"]
            _asn_rates     = payload["asn_rates"]
            _country_rates = payload["country_rates"]
            _global_rate   = payload["global_rate"]
        return payload
    except Exception as exc:
        logger.warning("Failed to load model from disk: %s", exc)
        return None


def start_background_training():
    """Launch training in a daemon thread (called at server startup)."""
    t = threading.Thread(target=train_model, daemon=True)
    t.start()
    logger.info("Background ML training started")


# ── Prediction ────────────────────────────────────────────────────────────────

def _risk_level(prob: float) -> str:
    if prob >= RISK_THRESHOLDS["CRITICAL"]: return "CRITICAL"
    if prob >= RISK_THRESHOLDS["HIGH"]:     return "HIGH"
    if prob >= RISK_THRESHOLDS["MEDIUM"]:   return "MEDIUM"
    return "LOW"


def _build_top_factors(feat: dict, importances: List[dict], asn_rates: dict,
                       country_rates: dict, global_rate: float) -> List[dict]:
    """Build human-readable top 3 risk factor explanations."""
    factors = []

    asn_rate = asn_rates.get(feat["asn_str"], global_rate)
    delta_asn = asn_rate - global_rate
    if abs(delta_asn) > 0.02:
        factors.append({
            "factor":      "ASN Historical Pattern",
            "detail":      "%s has %.1f%% observed threat rate (baseline %.1f%%)" % (
                           feat["asn_str"] or "Unknown ASN",
                           asn_rate * 100, global_rate * 100),
            "direction":   "risk" if delta_asn > 0 else "safe",
            "weight":      round(importances[5]["importance"] if len(importances) > 5 else 0.2, 3),
            "value":       round(asn_rate * 100, 1),
        })

    country_rate = country_rates.get(feat["country"], global_rate)
    delta_ctry   = country_rate - global_rate
    if abs(delta_ctry) > 0.02 and feat["country"] not in ("Unknown", ""):
        factors.append({
            "factor":      "Geographic Pattern",
            "detail":      "%s has %.1f%% observed threat rate (baseline %.1f%%)" % (
                           feat["country"], country_rate * 100, global_rate * 100),
            "direction":   "risk" if delta_ctry > 0 else "safe",
            "weight":      round(importances[6]["importance"] if len(importances) > 6 else 0.15, 3),
            "value":       round(country_rate * 100, 1),
        })

    pl = feat["prefix_length"]
    if pl <= 16:
        factors.append({
            "factor":    "Very Large Prefix Block",
            "detail":    "/%d contains %s addresses — large blocks often host diverse infrastructure" % (
                         pl, "{:,}".format(2 ** (32 - pl))),
            "direction": "risk",
            "weight":    round(importances[1]["importance"] if len(importances) > 1 else 0.12, 3),
            "value":     pl,
        })
    elif pl >= 28:
        factors.append({
            "factor":    "Very Small Prefix Block",
            "detail":    "/%d is a narrow dedicated block — unusual routing may indicate specialized use" % pl,
            "direction": "neutral",
            "weight":    round(importances[1]["importance"] if len(importances) > 1 else 0.1, 3),
            "value":     pl,
        })

    vis = feat["bgp_visibility"]
    if vis < 80.0 and vis > 0:
        factors.append({
            "factor":    "Low BGP Visibility",
            "detail":    "Only %.1f%% of RIS peers see this route — poorly propagated or recently announced" % vis,
            "direction": "risk",
            "weight":    round(importances[2]["importance"] if len(importances) > 2 else 0.1, 3),
            "value":     vis,
        })

    if feat["is_anycast"]:
        factors.append({
            "factor":    "Anycast Network",
            "detail":    "Anycast routing detected — shared CDN/DNS infrastructure, lower individual IP risk",
            "direction": "safe",
            "weight":    round(importances[4]["importance"] if len(importances) > 4 else 0.08, 3),
            "value":     1,
        })

    geo = feat["geo_consensus"]
    if geo <= 1:
        factors.append({
            "factor":    "Low GeoIP Consensus",
            "detail":    "Only %d/4 providers returned a country — IP may be unregistered or mis-routed" % geo,
            "direction": "risk",
            "weight":    round(importances[3]["importance"] if len(importances) > 3 else 0.1, 3),
            "value":     geo,
        })

    # Sort by weight descending, return top 3
    factors.sort(key=lambda x: x["weight"], reverse=True)
    return factors[:4]


def _estimate_category_signals(feat: dict, prob: float, cat_rates: dict) -> List[dict]:
    """
    Estimate per-category signals.
    Uses the ASN-level category breakdown from training data + global rates.
    """
    signals = []
    for cat in CATEGORIES:
        global_cat_rate = cat_rates.get(cat, 0.0)
        asn_boost = 0.0
        # Amplify by threat probability
        adjusted = (global_cat_rate / 100.0) * (prob / (cat_rates.get("attacks", 12) / 100 + 0.01))
        adjusted = min(adjusted * 100, 95.0)
        if adjusted > 2.0 or global_cat_rate > 1.0:
            signals.append({
                "category": cat,
                "signal_pct": round(adjusted, 1),
            })
    signals.sort(key=lambda x: x["signal_pct"], reverse=True)
    return signals[:6]


def predict(ip: str, ripestat: dict = None, bgp: dict = None, geo: dict = None) -> dict:
    """
    Predict threat probability for an IP.

    Parameters
    ----------
    ip      : str — the IP address string
    ripestat: dict — from search_results.ripestat
    bgp     : dict — from search_results.bgp_info
    geo     : dict — from search_results.geography

    Returns dict with prediction, probability, risk_level, top_factors, etc.
    """
    with _state_lock:
        model_ready = _model is not None
        local_meta  = _meta
        asn_r       = _asn_rates
        cty_r       = _country_rates
        g_rate      = _global_rate

    not_ready_resp = {
        "status":            "model_not_ready",
        "message":           "ML model is still training. Please retry in ~60 seconds.",
        "training_progress": True,
    }
    if not model_ready:
        return not_ready_resp

    ripestat  = ripestat or {}
    bgp       = bgp or {}
    geo_dict  = geo or {}

    asn_str   = ripestat.get("announced_asn") or bgp.get("asn") or ""
    prefix_s  = ripestat.get("prefix", "")
    vis_str   = ripestat.get("visibility", "")
    geo_cnt, country = _geo_consensus(geo_dict)

    feat = {
        "ip":             ip,
        "asn_str":        asn_str,
        "asn_number":     _parse_asn_number(asn_str),
        "prefix_length":  _parse_prefix_length(prefix_s),
        "bgp_visibility": _parse_visibility(vis_str),
        "geo_consensus":  geo_cnt,
        "is_anycast":     1 if bgp.get("is_anycast") else 0,
        "country":        country,
    }

    import numpy as np
    X = np.array([[
        feat["asn_number"],
        feat["prefix_length"],
        feat["bgp_visibility"],
        feat["geo_consensus"],
        feat["is_anycast"],
        asn_r.get(asn_str, g_rate),
        cty_r.get(country, g_rate),
    ]], dtype=np.float32)

    with _state_lock:
        prob = float(_model.predict_proba(X)[0, 1])
        importances = local_meta.get("feature_importances", []) if local_meta else []

    risk  = _risk_level(prob)
    score = round(prob * 100, 1)

    # Load cat_rates from disk cache for category signals
    try:
        with open(MODEL_CACHE_PATH, "rb") as f:
            payload = pickle.load(f)
        cat_rates = payload.get("cat_rates", {})
    except Exception:
        cat_rates = {c: 2.0 for c in CATEGORIES}

    top_factors       = _build_top_factors(feat, importances, asn_r, cty_r, g_rate)
    category_signals  = _estimate_category_signals(feat, prob, cat_rates)

    # Confidence — based on how decisive the probability is
    distance = abs(prob - 0.5)
    confidence = "HIGH" if distance > 0.3 else "MEDIUM" if distance > 0.15 else "LOW"

    return {
        "status":            "success",
        "ip":                ip,
        "threat_probability": score,
        "risk_level":        risk,
        "risk_color":        RISK_COLORS[risk],
        "prediction":        "THREAT" if prob >= 0.5 else "CLEAN",
        "confidence":        confidence,
        "top_factors":       top_factors,
        "category_signals":  category_signals,
        "input_features": {
            "asn":              asn_str or "Unknown",
            "prefix":           prefix_s or "Unknown",
            "prefix_length":    feat["prefix_length"],
            "bgp_visibility":   feat["bgp_visibility"],
            "geo_consensus":    feat["geo_consensus"],
            "country":          country,
            "is_anycast":       bool(feat["is_anycast"]),
            "asn_threat_rate":  round(asn_r.get(asn_str, g_rate) * 100, 1),
            "country_threat_rate": round(cty_r.get(country, g_rate) * 100, 1),
        },
        "model_info": {
            "trained_at":       local_meta.get("trained_at", "Unknown") if local_meta else "Unknown",
            "n_records":        local_meta.get("n_records", 0) if local_meta else 0,
            "n_threats":        local_meta.get("n_threats", 0) if local_meta else 0,
            "test_accuracy":    local_meta.get("test_accuracy", 0) if local_meta else 0,
            "test_auc_roc":     local_meta.get("test_auc_roc", 0) if local_meta else 0,
            "model_type":       local_meta.get("model_type", "RF") if local_meta else "RF",
            "features_used":    FEATURE_NAMES,
        },
        "disclaimer": (
            "Statistical estimate based on patterns in %d observed OSINT records. "
            "Not ground truth — a clean prediction does not mean the IP is safe. "
            "Use as one signal among many." % (local_meta.get("n_records", 0) if local_meta else 0)
        ),
    }


def get_model_info() -> dict:
    """Return current model metadata."""
    with _state_lock:
        ready = _model is not None
        meta  = _meta

    if not ready:
        return {
            "status":  "not_ready",
            "message": "Model is still training in the background.",
            "training_in_progress": _training_in_progress,
        }
    return {"status": "ready", **meta}
