from collections import defaultdict
from datetime import timedelta
from auth_log_parser import parse_auth_log_folder

def detect_brute_force(entries=None, folder_path=None):
    if entries is None:
        if not folder_path:
            raise ValueError("Must provide either entries or folder_path.")
        entries = parse_auth_log_folder(folder_path)

    failed_logins_by_ip = defaultdict(list)
    for entry in entries:
        if entry["status"] == "Failed":
            failed_logins_by_ip[entry["ip"]].append(entry["timestamp"])

    suspicious_ips = []

    for ip, times in failed_logins_by_ip.items():
        times.sort()
        for i in range(len(times) - 4):
            if times[i + 4] - times[i] <= timedelta(minutes=1):
                suspicious_ips.append((ip, len(failed_logins_by_ip[ip])))
                break

    return suspicious_ips
