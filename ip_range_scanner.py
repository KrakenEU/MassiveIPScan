#!/usr/bin/env python3
import subprocess
import ipaddress
import pandas as pd
import re
import os

XLSX_FILE = "DC1_DC2 Ranges.xlsx"
MAX_PORT = 65535
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


def scan_ip(ip_address: str, max_port: int = MAX_PORT):
    for port in range(1, max_port + 1):
        proc = subprocess.Popen(
            [f'bash -c "/bin/echo \'\' > /dev/tcp/{ip_address}/{port} 2>&/dev/null"'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
        )
        (out, err) = proc.communicate()
        if b"ambiguous redirect" in out:
            return port
    return None


def safe_filename(range_str: str) -> str:
    return range_str.replace("/", "_").replace(":", "_").replace(" ", "_") + ".txt"


def scan_range(range_str: str):
    reachable = {}   # ip -> port
    unreachable = []

    total_ips = sum(1 for _ in ip_range_iter(range_str))
    scanned = 0

    for ip in ip_range_iter(range_str):
        scanned += 1
        print(f"  [{scanned}/{total_ips}] Scanning {ip} ...", end=" ", flush=True)
        open_port = scan_ip(ip)
        if open_port is not None:
            reachable[ip] = open_port
            print(f"REACHABLE (port {open_port})")
        else:
            unreachable.append(ip)
            print("unreachable")

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

    print(f"  -> Results saved to: {filename}")


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
        print(f"\n[{i}/{len(ranges)}] Scanning range: {range_str}")
        try:
            reachable, unreachable = scan_range(range_str)
            write_result(range_str, reachable, unreachable)
        except Exception as e:
            print(f"  [ERROR] Failed scanning range '{range_str}': {e}")

    print("\nAll ranges processed.")


if __name__ == "__main__":
    main()
