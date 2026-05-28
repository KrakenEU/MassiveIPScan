#!/usr/bin/env python3

import nmap
import ipaddress
import json
import threading
import signal
import sys
import os
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
INPUT_FILE     = "input.txt"
MAX_THREADS    = 4
MAX_PORT       = 65535
PER_IP_TIMEOUT = 120
NMAP_ARGS = (
    "-Pn "
    "-p- "
    "-T4 "
    "--open "
    "-n "
    "--max-retries 1 "
    "--min-rate 1000 "
    "--host-timeout 60s "
    "--defeat-rst-ratelimit"
)

# Thread-safe print
_print_lock = threading.Lock()

def tprint(thread_id: int, msg: str):
    with _print_lock:
        print(f"[Thread-{thread_id}] {msg}", flush=True)

# Input: read and validate IPs from file
def load_ips(filepath: str) -> list[str]:
    if not os.path.isfile(filepath):
        print(f"[ERROR] Input file not found: {filepath}")
        sys.exit(1)

    seen    = set()
    valid   = []
    skipped = 0

    with open(filepath, "r") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()

            # skip blanks and comments
            if not line or line.startswith("#"):
                continue

            # validate
            try:
                ip = str(ipaddress.IPv4Address(line))
            except ipaddress.AddressValueError:
                print(f"  [SKIP] Line {lineno}: '{line}' is not a valid IPv4 address.")
                skipped += 1
                continue

            # deduplicate
            if ip in seen:
                print(f"  [SKIP] Line {lineno}: '{ip}' is a duplicate — ignoring.")
                skipped += 1
                continue

            seen.add(ip)
            valid.append(ip)

    return valid, skipped


def split_list(ips: list[str], n: int) -> list[list[str]]:
    size   = max(1, len(ips) // n)
    chunks = [ips[i:i + size] for i in range(0, len(ips), size)]
    # if rounding left an extra tiny chunk, merge it into the last one
    if len(chunks) > n:
        chunks[n - 1].extend(chunks[n])
        chunks = chunks[:n]
    return [c for c in chunks if c]

# Per-IP scan
def scan_ip_nmap(nm: nmap.PortScanner,ip: str,thread_id: int) -> list[int] | None:
    tprint(thread_id, f"scanning {ip} ...")

    error_holder = [None]
    done_event   = threading.Event()

    def do_scan():
        try:
            nm.scan(hosts=ip, arguments=NMAP_ARGS)
        except Exception as e:
            error_holder[0] = e
        finally:
            done_event.set()

    t = threading.Thread(target=do_scan, daemon=True)
    t.start()
    triggered = done_event.wait(timeout=PER_IP_TIMEOUT)

    if not triggered:
        tprint(thread_id, f"  !! TIMEOUT ({PER_IP_TIMEOUT}s) on {ip} — skipping")
        return None

    if error_holder[0]:
        tprint(thread_id, f"  !! nmap error on {ip}: {error_holder[0]}")
        return None

    if ip not in nm.all_hosts():
        tprint(thread_id, f"  -> unreachable")
        return None

    open_ports = sorted([
        port
        for proto in nm[ip].all_protocols()
        for port, state in nm[ip][proto].items()
        if state["state"] == "open"
    ])

    if open_ports:
        tprint(thread_id, f"  -> REACHABLE — open ports: {open_ports}")
        return open_ports

    tprint(thread_id, f"  -> host up but no open ports found")
    return None

# Worker: scan a chunk of IPs
def scan_chunk(chunk: list[str], thread_id: int) -> list[dict]:
    nm      = nmap.PortScanner()
    results = []
    total   = len(chunk)

    for idx, ip in enumerate(chunk, 1):
        tprint(thread_id, f"[{idx}/{total}] {ip}")
        try:
            open_ports = scan_ip_nmap(nm, ip, thread_id)
        except Exception as e:
            tprint(thread_id, f"  !! unexpected error on {ip}: {e}")
            continue

        if open_ports:
            results.append({
                "ip":         ip,
                "open_ports": open_ports,
                "port_count": len(open_ports),
            })

    return results

# Output
def build_output(all_ips:    list[str],
                 hosts:      list[dict],
                 scan_start: datetime,
                 scan_end:   datetime) -> dict:
    return {
        "meta": {
            "schema_version":     "1.0",
            "source":             INPUT_FILE,
            "scan_start":         scan_start.isoformat(),
            "scan_end":           scan_end.isoformat(),
            "duration_seconds":   (scan_end - scan_start).total_seconds(),
            "total_ips_scanned":  len(all_ips),
            "total_reachable":    len(hosts),
            "total_unreachable":  len(all_ips) - len(hosts),
            "threads_used":       MAX_THREADS,
            "max_port":           MAX_PORT,
        },
        # sort by IP for deterministic output / easier Grafana queries
        "hosts": sorted(hosts, key=lambda h: ipaddress.IPv4Address(h["ip"]))
    }


def save_json(data: dict) -> str:
    ts       = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"scan_list_{ts}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    return filename

def main():
    signal.signal(signal.SIGINT, lambda *_: (print("\n[!] Interrupted."), sys.exit(1)))

    print("=" * 60)
    print("  IP List Scanner — Grafana/SNOW Edition")
    print("=" * 60)

    all_ips, skipped = load_ips(INPUT_FILE)

    if not all_ips:
        print("[ERROR] No valid IPs found in input.txt. Exiting.")
        return

    chunks = split_list(all_ips, MAX_THREADS)

    print(f"\nInput file : {INPUT_FILE}")
    print(f"Valid IPs  : {len(all_ips):,}  (skipped {skipped})")
    print(f"Threads    : {len(chunks)}  (~{len(chunks[0])} IPs each)")
    print(f"Ports      : 1-{MAX_PORT}")

    confirm = input("\nStart scan? [y/N]: ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        return

    all_hosts    = []
    results_lock = threading.Lock()
    scan_start   = datetime.now(timezone.utc)

    print(f"\nScan started at {scan_start.isoformat()}\n")

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {
            executor.submit(scan_chunk, chunk, tid): tid
            for tid, chunk in enumerate(chunks, 1)
        }
        for future in as_completed(futures):
            tid = futures[future]
            try:
                chunk_results = future.result()
                with results_lock:
                    all_hosts.extend(chunk_results)
            except Exception as e:
                print(f"[ERROR] Thread-{tid} failed: {e}")

    scan_end = datetime.now(timezone.utc)
    output   = build_output(all_ips, all_hosts, scan_start, scan_end)
    filename = save_json(output)

    print("\n" + "=" * 60)
    print(f"Scan complete.")
    print(f"  Duration    : {output['meta']['duration_seconds']:.1f}s")
    print(f"  Reachable   : {output['meta']['total_reachable']}")
    print(f"  Unreachable : {output['meta']['total_unreachable']}")
    print(f"  Output      : {filename}")
    print("=" * 60)


if __name__ == "__main__":
    main()
