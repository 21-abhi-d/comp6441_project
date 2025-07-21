from datetime import datetime, timedelta
from collections import defaultdict

def detect_intrusions(entries, max_attempts=5, window_minutes=2):
    """Detect IPs with too many failed login attempts in a short time window."""
    ip_timestamps = defaultdict(list)

    for entry in entries:
        if entry.get("status") == "Failed":
            timestamp = datetime.strptime(entry["timestamp"], "%Y-%m-%d %H:%M:%S")
            ip_timestamps[entry["ip"]].append(timestamp)

    suspicious_ips = []
    for ip, times in ip_timestamps.items():
        times.sort()
        for i in range(len(times) - max_attempts + 1):
            if times[i + max_attempts - 1] - times[i] <= timedelta(minutes=window_minutes):
                suspicious_ips.append((ip, max_attempts, window_minutes))
                break  # Flag once per IP

    return suspicious_ips