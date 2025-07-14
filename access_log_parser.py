import os
import re
from datetime import datetime

pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<path>.+?)\s+HTTP/\d\.\d"\s+(?P<status>\d+)\s+(?P<size>\d+)\s+"[^"]*"\s+"(?P<agent>[^"]*)"'
)

def parse_access_log_line(line):
    match = pattern.match(line)
    if not match:
        return None
    data = match.groupdict()
    data['timestamp'] = datetime.strptime(data['timestamp'], "%d/%b/%Y:%H:%M:%S %z")
    return data

def parse_access_log_folder(folder_path):
    all_entries = []
    total_lines = 0
    matched_lines = 0

    for filename in os.listdir(folder_path):
        filepath = os.path.join(folder_path, filename)
        if not filename.endswith(".log"):
            continue
        with open(filepath, "r") as f:
            for line in f:
                total_lines += 1
                result = parse_access_log_line(line.strip())
                if result:
                    result["source_file"] = filename
                    all_entries.append(result)
                    matched_lines += 1
                # Removed debug print here

    return all_entries
