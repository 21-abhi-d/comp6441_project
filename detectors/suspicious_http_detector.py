def detect_suspicious_http_methods(entries):
    suspicious_methods = {"PUT", "DELETE", "TRACE", "TRACK", "OPTIONS"}
    flagged = []

    for entry in entries:
        method = entry.get("method", "").upper()
        ip = entry.get("ip")
        path = entry.get("path")

        if method in suspicious_methods:
            flagged.append((ip, method, path))

    return flagged