from auth_log_parser import parse_log_file
from collections import defaultdict
from datetime import timedelta

entries = parse_log_file("sample_auth.log")

failed_logins_by_ip = defaultdict(list)
for entry in entries:
    if entry["status"] == "Failed":
        failed_logins_by_ip[entry["ip"]].append(entry["timestamp"])

# Detect brute-force: 5+ failures in 1 minute
suspicious_ips = []

for ip, times in failed_logins_by_ip.items():
    times.sort()
    for i in range(len(times) - 4):
        if times[i + 4] - times[i] <= timedelta(minutes=1):
            suspicious_ips.append(ip)
            break

print("\n Suspicious IPs (Brute-force attempts):")
for ip in suspicious_ips:
    print(f" - {ip} ({len(failed_logins_by_ip[ip])} failed attempts)")