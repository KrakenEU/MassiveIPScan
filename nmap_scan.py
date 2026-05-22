#!/usr/bin/env python3

import nmap
import ipaddress
import pandas as pd
import re
import os
import json
import threading
import signal
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout

# Configuration

XLSX_FILE        = "DC1_DC2 Ranges.xlsx"
MAX_PORT         = 65535
MAX_THREADS      = 3
PER_IP_TIMEOUT   = 120
NMAP_ARGS        = (
    "-T4 "
    "--open "
    "-n "
    "--max-retries 1 "
    "--min-rate 1000 "
    "--host-timeout 60s "
    "--defeat-rst-ratelimit"
)

RANGE_PATTERN = re.compile(
    r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
)

# Helpers

def is_valid_range(value: str) -> bool:
    if not isinstance(value, str):
        return False
    value = value.strip()
    if not RANGE_PATTERN.match(value):
        return False
    try:
        start_str, end_str = value.split("-")
        return int(ipaddress.IPv4Address(start_str.strip())) <= \
               int(ipaddress.IPv4Address(end_str.strip()))
    except Exception:
        return False


def ip_range_iter(range_str: str):
    start_str, end_str = range_str.strip().split("-")
    start = int(ipaddress.IPv4Address(start_str.strip()))
    end   = int(ipaddress.IPv4Address(end_str.strip()))
    for ip_int in range(start, end + 1):
        yield str(ipaddress.IPv4Address(ip_int))


def safe_filename(range_str: str) -> str:
    return range_str.replace("/", "_").replace(":", "_").replace(" ", "_") + ".json"


# Thread-safe print lock so lines from different threads don't interleave
_print_lock = threading.Lock()

def tprint(thread_label: str, msg: str):
    with _print_lock:
        print(f"[{thread_label}] {msg}", flush=True)


def scan_ip_nmap(nm: nmap.PortScanner, ip: str, thread_label: str) -> int | None:
    port_range = f"1-{MAX_PORT}"
    tprint(thread_label, f"  probing {ip} ports {port_range} ...")

    result_holder = [None]
    error_holder  = [None]

    def do_scan():
        try:
            nm.scan(hosts=ip, ports=port_range, arguments=NMAP_ARGS)
        except Exception as e:
            error_holder[0] = e

    scan_thread = threading.Thread(target=do_scan, daemon=True)
    scan_thread.start()
    scan_thread.join(timeout=PER_IP_TIMEOUT)

    if scan_thread.is_alive():
        tprint(thread_label, f"  !! TIMEOUT on {ip} after {PER_IP_TIMEOUT}s — skipping")
        # We can't kill the thread directly, but daemon=True means it won't
        # block program exit. Return None and move on.
        return None

    if error_holder[0]:
        tprint(thread_label, f"  !! nmap error on {ip}: {error_holder[0]}")
        return None

    if ip not in nm.all_hosts():
        return None

    open_ports = [
        port
        for proto in nm[ip].all_protocols()
        for port, state in nm[ip][proto].items()
        if state["state"] == "open"
    ]

    return min(open_ports) if open_ports else None


def scan_range(range_str: str) -> dict:
    """Scan every IP in the range. Returns a result dict."""
    label = range_str          # used as thread label in log lines
    nm    = nmap.PortScanner() # each thread gets its own scanner instance

    all_ips   = list(ip_range_iter(range_str))
    total     = len(all_ips)
    reachable   = {}
    unreachable = []

    tprint(label, f"Starting — {total} IPs to scan")

    for idx, ip in enumerate(all_ips, 1):
        tprint(label, f"[{idx}/{total}] scanning {ip}")
        try:
            open_port = scan_ip_nmap(nm, ip, label)
        except Exception as e:
            tprint(label, f"  !! unexpected error on {ip}: {e} — skipping")
            unreachable.append(ip)
            continue

        if open_port is not None:
            reachable[ip] = open_port
            tprint(label, f"  -> REACHABLE  port {open_port}")
        else:
            unreachable.append(ip)
            tprint(label, f"  -> unreachable")

    result = {
        "range":             range_str,
        "scanned_at":        datetime.utcnow().isoformat() + "Z",
        "total_ips":         total,
        "total_reachable":   len(reachable),
        "total_unreachable": len(unreachable),
        "reachable": [
            {"ip": ip, "first_open_port": port}
            for ip, port in reachable.items()
        ],
        "unreachable": unreachable,
    }

    filename = safe_filename(range_str)
    with open(filename, "w") as f:
        json.dump(result, f, indent=2)

    tprint(label, f"Done — saved to {filename} "
                  f"({len(reachable)} reachable / {len(unreachable)} unreachable)")
    return result

def main():
    # Graceful Ctrl-C
    signal.signal(signal.SIGINT, lambda *_: (print("\n[!] Interrupted."), sys.exit(1)))

    if not os.path.isfile(XLSX_FILE):
        print(f"[ERROR] File not found: {XLSX_FILE}")
        return

    try:
        df = pd.read_excel(XLSX_FILE, header=None, dtype=str)
    except Exception as e:
        print(f"[ERROR] Could not read Excel file: {e}")
        return

    ranges  = []
    skipped = 0
    for idx, value in df.iloc[:, 0].items():
        cell = str(value).strip() if pd.notna(value) else ""
        if is_valid_range(cell):
            ranges.append(cell)
        else:
            if cell and cell.lower() != "nan":
                print(f"[SKIP] Row {idx + 1}: '{cell}' is not a valid IP range.")
            skipped += 1

    print(f"\nFound {len(ranges)} valid range(s). "
          f"Skipped {skipped} non-range row(s). "
          f"Running up to {MAX_THREADS} ranges in parallel.\n")

    if not ranges:
        print("No valid ranges to scan. Exiting.")
        return

    # Each future maps to its range string for error reporting
    futures_map = {}
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for range_str in ranges:
            future = executor.submit(scan_range, range_str)
            futures_map[future] = range_str

        for future in as_completed(futures_map):
            range_str = futures_map[future]
            try:
                future.result(timeout=None)   # result already saved inside scan_range
            except Exception as e:
                print(f"[ERROR] Range '{range_str}' failed: {e}")

    print("\nAll ranges processed.")


if __name__ == "__main__":
    main()