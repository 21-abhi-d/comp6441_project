from collections import defaultdict
from datetime import datetime, timedelta
import re

def detect_port_scans(entries, threshold=10, window_minutes=5):
    ip_to_ports = defaultdict(list)

    for entry in entries:
        ip = entry["ip"]
        timestamp = entry["timestamp"]
        path = entry["path"]

        # Extract port from path if mentioned like ":8080", ":22"
        match = re.search(r":(\d+)", path)
        if match:
            port = match.group(1)
            ip_to_ports[ip].append((timestamp, port))

    flagged_ips = []
    for ip, attempts in ip_to_ports.items():
        # Sort by timestamp
        attempts.sort()
        ports_seen = set()
        start_time = None

        for ts, port in attempts:
            if not start_time:
                start_time = ts
            if ts - start_time > timedelta(minutes=window_minutes):
                # Reset window
                ports_seen = set()
                start_time = ts

            ports_seen.add(port)

            if len(ports_seen) >= threshold:
                flagged_ips.append((ip, len(ports_seen), window_minutes))
                break

    return flagged_ips
