#!/usr/bin/env python3
"""
bulk_scan_ua.py
---------------
Bulk-scan every IP in blocklist_net_ua.ipset and store the results in
DynamoDB using the same data structure as /api/search-ip.

Features:
  - 20 parallel threads for speed
  - Skips IPs already stored in DynamoDB (safe to re-run / resume)
  - TCP-only ping (no ICMP, no traceroute) — much faster for bulk
  - Live progress bar with ETA
  - Final report at the end

NOTE: This file has ~164,270 IPs. ipinfo.io free tier = 50,000/month.
      After 50K IPs, BGP data will show "BGP Lookup Unavailable".
      Geo + threat data will still be saved for all IPs.

Run command:
  cd "c:\\Users\\LENOVO\\OneDrive\\Desktop\\RM Project\\OSINT\\OSINT-Dashboard\\backend"
  python bulk_scan_ua.py
"""

import sys
import os
import time
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ── Path setup ────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

# Load .env BEFORE any other import so boto3 picks up credentials
from dotenv import load_dotenv
load_dotenv(os.path.join(SCRIPT_DIR, ".env"))

# ── Configuration ─────────────────────────────────────────────────────────────
IPSET_FILE    = os.path.join(SCRIPT_DIR, "..", "firehol_repo", "blocklist_net_ua.ipset")  # <-- changed
MAX_WORKERS   = 20      # parallel threads (increase to 30 if you have fast internet)
SKIP_EXISTING = True    # True = skip IPs already in DynamoDB (resume-safe)

# ── Import modules ────────────────────────────────────────────────────────────
print("\n[Step 1/3] Importing scan & database modules...")
from database import get_cached_search, save_cached_search

print("[Step 2/3] Importing scan functions from main.py...")
from main import (
    lookup_single_ip_geo,
    get_bgp_info,
    fetch_ripestat_intelligence,
    probe_tcp_latency,
    threat_ips,
    threat_networks,
    BEHAVIORAL_CATEGORIES,
    process_map_data,
    ensure_firehol_repo,
)

print("[Step 3/3] Loading FireHOL intelligence data into RAM (may take 30-90 sec)...")
ensure_firehol_repo()   # make sure git repo is up-to-date
process_map_data()      # parse all CIDR files into memory
print("           FireHOL data ready.\n")

# ── Thread-safe progress counters ────────────────────────────────────────────
_lock     = threading.Lock()
_stats    = {"done": 0, "saved": 0, "skipped": 0, "failed": 0, "total": 0}
_start_ts = time.time()


def _print_progress():
    with _lock:
        done    = _stats["done"]
        total   = _stats["total"]
        elapsed = time.time() - _start_ts
        rate    = done / elapsed if elapsed > 0 else 0.001
        remain  = (total - done) / rate
        pct     = (done / total * 100) if total > 0 else 0
        eta     = datetime.fromtimestamp(time.time() + remain).strftime("%H:%M:%S")

        print(
            f"\r  [{done:>6}/{total}] {pct:5.1f}%  |  "
            f"Saved: {_stats['saved']:>6}  "
            f"Skipped: {_stats['skipped']:>6}  "
            f"Failed: {_stats['failed']:>4}  |  "
            f"Speed: {rate:5.1f}/s  ETA: {eta}   ",
            end="", flush=True,
        )


# ── Fast ping (TCP only — no ICMP, no traceroute) ─────────────────────────────
def _fast_ping(ip: str) -> dict:
    """TCP-connect probe on common ports. No ICMP, no traceroute."""
    result = probe_tcp_latency(ip, ports=(443, 80, 53, 8080), timeout=1.2)
    if result:
        return result
    return {
        "rtt":              "N/A",
        "rtt_ms":           None,
        "min_ms":           None,
        "max_ms":           None,
        "packets_received": 0,
        "status":           "Offline / Filtered",
    }


# ── Single IP scan ────────────────────────────────────────────────────────────
def scan_and_store(ip: str) -> str:
    """Run scan (same as /api/search-ip but no traceroute) and save to DynamoDB."""

    # Validate IP
    try:
        target      = ipaddress.ip_address(ip)
        target_int  = int(target)
        first_octet = target.packed[0]
    except ValueError:
        with _lock:
            _stats["failed"] += 1
        return "invalid"

    # Skip if already stored in DynamoDB
    if SKIP_EXISTING:
        try:
            cached = get_cached_search(ip)
            if cached:
                with _lock:
                    _stats["skipped"] += 1
                return "skipped"
        except Exception:
            pass  # DynamoDB check failed — proceed to scan

    try:
        # 1. Geo lookup (RAM — instant)
        geography = lookup_single_ip_geo(ip)

        # 2. Threat category check (RAM — instant)
        threats = []
        for cat in BEHAVIORAL_CATEGORIES:
            if ip in threat_ips[cat]:
                threats.append(cat)
                continue
            for start_int, end_int in threat_networks[cat].get(first_octet, []):
                if start_int <= target_int <= end_int:
                    threats.append(cat)
                    break

        # 3. BGP / ASN info  (ipinfo.io — ~1-3 sec)
        bgp_data = get_bgp_info(ip)

        # 4. RIPEstat intelligence  (3 parallel API calls — ~3-5 sec)
        ripestat_data = fetch_ripestat_intelligence(ip)

        # Fallbacks if RIPEstat was rate-limited
        if ripestat_data["announced_asn"] == "Unknown" and bgp_data.get("asn") not in (None, "Unknown"):
            ripestat_data["announced_asn"] = bgp_data["asn"]
        if ripestat_data["prefix"] == "Unknown":
            ripestat_data["prefix"] = f"{ip}/32"
        if ripestat_data["holder_registry"]["country"] in ("Unknown", "", None) and bgp_data.get("country"):
            ripestat_data["holder_registry"]["country"] = bgp_data["country"]
            ripestat_data["holder_registry"]["city"]    = bgp_data.get("city") or "Registry Node"

        # 5. Fast TCP ping — no ICMP, no traceroute
        ping_data = _fast_ping(ip)

        # 6. Build result dict (same structure as /api/search-ip)
        result = {
            "ip":               ip,
            "geography":        geography,
            "behavioral_flags": threats,
            "bgp_info":         bgp_data,
            "telemetry":        ping_data,
            "ripestat":         ripestat_data,
        }

        # 7. Save to DynamoDB
        save_cached_search(ip, result)

        with _lock:
            _stats["saved"] += 1
        return "saved"

    except Exception as exc:
        with _lock:
            _stats["failed"] += 1
        return f"error: {exc}"


# ── Load IPs from .ipset file ─────────────────────────────────────────────────
def load_ips(filepath: str) -> list:
    ips = []
    with open(filepath, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                ipaddress.ip_address(line)  # only accept exact IPs (skip CIDRs)
                ips.append(line)
            except ValueError:
                pass  # skip CIDRs / malformed lines
    return ips


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    sep = "=" * 70

    print(sep)
    print("  OSINT Bulk Scanner  ->  DynamoDB")
    print(f"  File    : {os.path.basename(IPSET_FILE)}")
    print(f"  Threads : {MAX_WORKERS}")
    print(f"  Resume  : {'Yes - skipping already-stored IPs' if SKIP_EXISTING else 'No - re-scanning everything'}")
    print(f"  WARNING : ~164K IPs. ipinfo.io free = 50K/month.")
    print(f"            After 50K, BGP shows 'Unavailable' — geo+threat still saved.")
    print(sep)

    # Load IP list
    if not os.path.isfile(IPSET_FILE):
        print(f"\n  ERROR: File not found -> {IPSET_FILE}")
        sys.exit(1)

    ips = load_ips(IPSET_FILE)
    _stats["total"] = len(ips)
    print(f"\n  Loaded {len(ips):,} IPs from file")
    print(f"  Estimated time: 15-20 hours (20 threads)")
    print(f"  Starting scan...\n")

    global _start_ts
    _start_ts = time.time()

    # Run in parallel
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(scan_and_store, ip): ip for ip in ips}
        for _ in as_completed(futures):
            with _lock:
                _stats["done"] += 1
            _print_progress()

    # Final report
    elapsed_min = (time.time() - _start_ts) / 60
    print(f"\n\n{sep}")
    print(f"  FINISHED in {elapsed_min:.1f} minutes  ({elapsed_min/60:.1f} hours)")
    print(f"")
    print(f"  Saved to DynamoDB  : {_stats['saved']:>8,}")
    print(f"  Already existed    : {_stats['skipped']:>8,}")
    print(f"  Failed             : {_stats['failed']:>8,}")
    print(f"  Total processed    : {_stats['done']:>8,}")
    print(sep)
    print("\n  Done! Open AWS DynamoDB console to view results.")
    print(f"  Region: eu-north-1  |  Table: researchProject01\n")


if __name__ == "__main__":
    main()
