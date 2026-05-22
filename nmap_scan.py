#!/usr/bin/env python3
import nmap
import ipaddress
import pandas as pd
import re
import os

XLSX_FILE = "DC1_DC2 Ranges.xlsx"
MAX_PORT = 65535

# Nmap tuning — adjust to taste:
#   -T4        aggressive timing (fast network); use -T3 on flaky links
#   --open     only report open ports (skip closed/filtered noise)
#   --min-rate sends at least N packets/sec; raise for faster scans on LAN
#   -n         skip DNS resolution (saves time)
#   --max-retries 1  don't retry dropped packets
NMAP_ARGS = "-T4 --open -n --max-retries 1 --min-rate 1000"

RANGE_PATTERN = re.compile(
    r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
)


def is_valid_range(value: str) -> bool:
    if not isinstance(value, str):
        return False
    value = value.strip()
    if not RANGE_PATTERN.match(value):
        return False
    try:
        start_str, end_str = value.split("-")
        start = ipaddress.IPv4Address(start_str.strip())
        end = ipaddress.IPv4Address(end_str.strip())
        return int(start) <= int(end)
    except Exception:
        return False


def ip_range_iter(range_str: str):
    start_str, end_str = range_str.strip().split("-")
    start = int(ipaddress.IPv4Address(start_str.strip()))
    end = int(ipaddress.IPv4Address(end_str.strip()))
    for ip_int in range(start, end + 1):
        yield str(ipaddress.IPv4Address(ip_int))


def scan_ip_nmap(nm: nmap.PortScanner, ip: str) -> int | None:
    """
    Scan all 65535 ports on a single IP with nmap.
    Returns the lowest open port found, or None if unreachable.
    """
    port_range = f"1-{MAX_PORT}"
    print(f"\r    running nmap on {ip} (ports {port_range}) ...", end="", flush=True)

    try:
        nm.scan(hosts=ip, ports=port_range, arguments=NMAP_ARGS)
    except Exception as e:
        print(f"\n    [WARN] nmap error on {ip}: {e}")
        return None

    if ip not in nm.all_hosts():
        return None

    open_ports = [
        port
        for proto in nm[ip].all_protocols()
        for port, state in nm[ip][proto].items()
        if state["state"] == "open"
    ]

    if open_ports:
        return min(open_ports)   # return the lowest open port found
    return None


def safe_filename(range_str: str) -> str:
    return range_str.replace("/", "_").replace(":", "_").replace(" ", "_") + ".txt"


def scan_range(range_str: str):
    nm = nmap.PortScanner()
    reachable = {}
    unreachable = []

    all_ips = list(ip_range_iter(range_str))
    total = len(all_ips)

    for idx, ip in enumerate(all_ips, 1):
        print(f"  [{idx}/{total}] Scanning {ip} ...", flush=True)
        open_port = scan_ip_nmap(nm, ip)
        print()  # newline after \r progress
        if open_port is not None:
            reachable[ip] = open_port
            print(f"  -> REACHABLE (first open port: {open_port})")
        else:
            unreachable.append(ip)
            print(f"  -> unreachable / all ports closed")

    return reachable, unreachable


def write_result(range_str: str, reachable: dict, unreachable: list):
    filename = safe_filename(range_str)
    with open(filename, "w") as f:
        f.write(f"Range: {range_str}\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"Reachable IPs ({len(reachable)}):\n")
        f.write("-" * 40 + "\n")
        for ip, port in reachable.items():
            f.write(f"  {ip}  ->  port {port}\n")

        f.write(f"\nUnreachable IPs ({len(unreachable)}):\n")
        f.write("-" * 40 + "\n")
        for ip in unreachable:
            f.write(f"  {ip}\n")

        f.write("\n" + "=" * 60 + "\n")
        f.write(f"Total reachable:   {len(reachable)}\n")
        f.write(f"Total unreachable: {len(unreachable)}\n")

    print(f"  -> Results saved to: {filename}\n")


def main():
    if not os.path.isfile(XLSX_FILE):
        print(f"[ERROR] File not found: {XLSX_FILE}")
        return

    try:
        df = pd.read_excel(XLSX_FILE, header=None, dtype=str)
    except Exception as e:
        print(f"[ERROR] Could not read Excel file: {e}")
        return

    column_a = df.iloc[:, 0]
    ranges = []
    skipped = 0

    for idx, value in column_a.items():
        cell = str(value).strip() if pd.notna(value) else ""
        if is_valid_range(cell):
            ranges.append(cell)
        else:
            if cell and cell.lower() != "nan":
                print(f"[SKIP] Row {idx + 1}: '{cell}' is not a valid IP range.")
            skipped += 1

    print(f"\nFound {len(ranges)} valid range(s). Skipped {skipped} non-range row(s).\n")

    if not ranges:
        print("No valid ranges to scan. Exiting.")
        return

    for i, range_str in enumerate(ranges, 1):
        print(f"\n{'='*60}")
        print(f"[{i}/{len(ranges)}] Scanning range: {range_str}")
        print(f"{'='*60}")
        try:
            reachable, unreachable = scan_range(range_str)
            write_result(range_str, reachable, unreachable)
        except Exception as e:
            print(f"  [ERROR] Failed scanning range '{range_str}': {e}")

    print("All ranges processed.")


if __name__ == "__main__":
    main()