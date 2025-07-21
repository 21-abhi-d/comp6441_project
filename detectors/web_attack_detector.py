from access_log_parser import parse_access_log_folder

def detect_web_attacks(entries=None, folder_path=None):
    if entries is None:
        if not folder_path:
            raise ValueError("Must provide either entries or folder_path")
        entries = parse_access_log_folder(folder_path)

    def is_suspicious(entry):
        path = entry.get("path", "")
        agent = entry.get("agent", "").lower()

        if "../" in path or "..%2f" in path:
            return "Path Traversal"
        if "'" in path or "1=1" in path or "union" in path.lower():
            return "SQL Injection"
        if agent in ["", "-", "sqlmap", "curl/7.58.0", "curl/7.64.1", "curl/7.80.0"]:
            return "Suspicious User-Agent"
        if any(keyword in path for keyword in ["/admin", "/wp-admin", "/config", "/.env"]):
            return "Access to Sensitive Path"

        return None

    suspicious_entries = []
    for entry in entries:
        reason = is_suspicious(entry)
        if reason:
            suspicious_entries.append((entry["ip"], reason, entry["path"]))

    return suspicious_entries
