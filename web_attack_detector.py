from access_log_parser import parse_access_log_file

entries = parse_access_log_file("sample_access.log")

def is_suspicious(entry):
    path = entry["path"]
    agent = entry["agent"].lower()
    
    # Detect path traversal
    if "../" in path or "..%2f" in path:
        return "Path Traversal"

    # Detect SQL injection pattern
    if "'" in path or "1=1" in path or "union" in path.lower():
        return "SQL Injection"

    # Detect suspicious user agents
    if agent in ["", "-", "sqlmap", "curl/7.58.0"]:
        return "Suspicious User-Agent"

    # Detect access to restricted paths
    if any(keyword in path for keyword in ["/admin", "/wp-admin", "/config", "/.env"]):
        return "Access to Sensitive Path"

    return None

print("\n Web Attack Detection Results:")
for entry in entries:
    reason = is_suspicious(entry)
    if reason:
        print(f" - {entry['ip']} triggered [{reason}] on path: {entry['path']}")
