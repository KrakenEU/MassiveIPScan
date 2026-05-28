#!/usr/bin/env python3
"""
IP Range Scanner — Grafana/SNOW ingest edition
Prompts for a start/end IP, splits the range across threads,
scans all 65535 ports per IP with nmap, records ALL open ports,
and writes a single structured .json file ready for ingestion.

Requirements:
    pip install python-nmap
    nmap must be installed: sudo apt install nmap  /  brew install nmap
    Recommended: run as root for SYN scan accuracy
"""

import nmap
import ipaddress
import json
import threading
import signal
import sys
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed


MAX_THREADS = 4
MAX_PORT    = 65535
NMAP_ARGS = (
    "-Pn "
    "-p- "
    "-T5 "
    "--open "
    "-n "
    "--max-retries 1 "
    "--min-rate 5000 "
    "--defeat-rst-ratelimit"
)


_print_lock = threading.Lock()

def tprint(thread_id: int, msg: str):
    with _print_lock:
        print(f"[Thread-{thread_id}] {msg}", flush=True)


def prompt_ip(label: str) -> ipaddress.IPv4Address:
    while True:
        raw = input(f"  {label}: ").strip()
        try:
            return ipaddress.IPv4Address(raw)
        except ipaddress.AddressValueError:
            print(f"  [!] '{raw}' is not a valid IPv4 address. Try again.")


def get_range() -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]:
    print("\nEnter the IP range to scan:")
    while True:
        start = prompt_ip("Start IP")
        end   = prompt_ip("End IP  ")
        if int(start) > int(end):
            print("  [!] Start IP must be <= End IP. Try again.\n")
        else:
            return start, end


def split_range(start: ipaddress.IPv4Address,
                end:   ipaddress.IPv4Address,
                n:     int) -> list[list[str]]:
    total  = int(end) - int(start) + 1
    size   = max(1, total // n)
    chunks = []
    cur    = int(start)
    end_i  = int(end)
    for i in range(n):
        chunk_start = cur
        chunk_end   = cur + size - 1 if i < n - 1 else end_i
        chunk_end   = min(chunk_end, end_i)
        chunks.append([str(ipaddress.IPv4Address(ip))
                        for ip in range(chunk_start, chunk_end + 1)])
        cur = chunk_end + 1
        if cur > end_i:
            break
    return [c for c in chunks if c]


def scan_ip_nmap(nm: nmap.PortScanner,
                 ip: str,
                 thread_id: int) -> list[int] | None:

    tprint(thread_id, f"scanning {ip} ...")

    try:
        nm.scan(hosts=ip, arguments=NMAP_ARGS)
    except Exception as e:
        tprint(thread_id, f"  !! nmap error on {ip}: {e}")
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


def build_output(start:      ipaddress.IPv4Address,
                 end:        ipaddress.IPv4Address,
                 hosts:      list[dict],
                 scan_start: datetime,
                 scan_end:   datetime) -> dict:
    total_ips = int(end) - int(start) + 1
    return {
        "meta": {
            "schema_version":     "1.0",
            "scan_start":         scan_start.isoformat(),
            "scan_end":           scan_end.isoformat(),
            "duration_seconds":   (scan_end - scan_start).total_seconds(),
            "range_start":        str(start),
            "range_end":          str(end),
            "total_ips_scanned":  total_ips,
            "total_reachable":    len(hosts),
            "total_unreachable":  total_ips - len(hosts),
            "threads_used":       MAX_THREADS,
            "max_port":           MAX_PORT,
        },
        "hosts": sorted(hosts, key=lambda h: ipaddress.IPv4Address(h["ip"]))
    }


def save_json(data: dict, start: ipaddress.IPv4Address) -> str:
    ts       = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"scan_{start}_{ts}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    return filename


def main():
    signal.signal(signal.SIGINT, lambda *_: (print("\n[!] Interrupted."), sys.exit(1)))

    print("=" * 60)
    print("  IP Range Scanner — Grafana/SNOW Edition")
    print("=" * 60)

    start, end = get_range()
    total_ips  = int(end) - int(start) + 1

    print(f"\nRange  : {start}  ->  {end}")
    print(f"IPs    : {total_ips:,}")
    print(f"Threads: {MAX_THREADS}")
    print(f"Ports  : 1-{MAX_PORT}")
    confirm = input("\nStart scan? [y/N]: ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        return

    chunks       = split_range(start, end, MAX_THREADS)
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
    output   = build_output(start, end, all_hosts, scan_start, scan_end)
    filename = save_json(output, start)

    print("\n" + "=" * 60)
    print(f"Scan complete.")
    print(f"  Duration    : {output['meta']['duration_seconds']:.1f}s")
    print(f"  Reachable   : {output['meta']['total_reachable']}")
    print(f"  Unreachable : {output['meta']['total_unreachable']}")
    print(f"  Output      : {filename}")
    print("=" * 60)


if __name__ == "__main__":
    main()
EOF