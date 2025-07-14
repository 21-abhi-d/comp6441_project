import os
import re
from datetime import datetime

pattern = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<status>\w+)\s+password for (?P<validity>invalid user|user)?\s*(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<port>\d+)\s+ssh2'
)

def parse_auth_log_line(line):
    match = pattern.match(line)
    if not match:
        return None
    data = match.groupdict()
    CURRENT_YEAR = datetime.now().year
    date_str = f"{CURRENT_YEAR} {data['month']} {data['day']} {data['time']}"
    data['timestamp'] = datetime.strptime(date_str, "%Y %b %d %H:%M:%S")
    return data

def parse_auth_log_folder(folder_path):
    entries = []
    for filename in os.listdir(folder_path):
        if filename.endswith(".log"):
            filepath = os.path.join(folder_path, filename)
            with open(filepath, "r") as f:
                for line in f:
                    result = parse_auth_log_line(line.strip())
                    if result:
                        result["source_file"] = filename  # Optional: track source file
                        entries.append(result)
    return entries
