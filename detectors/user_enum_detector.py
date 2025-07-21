import re
from collections import defaultdict

def detect_user_enumeration(entries, threshold=5):
    """
    Detects user enumeration attempts in parsed auth.log entries.

    Args:
        entries (list of dict): Parsed log entries from auth.log
        threshold (int): Minimum number of unique usernames per IP to consider as enumeration

    Returns:
        list of tuples: [(ip, usernames_tried), ...]
    """

    ip_to_usernames = defaultdict(set)

    for entry in entries:
        message = entry.get("message", "").lower()
        ip = entry.get("ip")

        # Detect lines like: "invalid user <username> from <ip>"
        match = re.search(r"invalid user (\w+)", message)
        if match and ip:
            username = match.group(1)
            ip_to_usernames[ip].add(username)

    suspicious_ips = []
    for ip, usernames in ip_to_usernames.items():
        if len(usernames) >= threshold:
            suspicious_ips.append((ip, list(usernames)))

    return suspicious_ips
