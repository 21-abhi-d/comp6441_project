from collections import defaultdict

def detect_dos_attempts(entries, threshold=100):
    ip_counts = defaultdict(int)

    for entry in entries:
        ip = entry.get("ip")
        if ip:
            ip_counts[ip] += 1

    suspects = [(ip, count) for ip, count in ip_counts.items() if count >= threshold]
    return suspects
