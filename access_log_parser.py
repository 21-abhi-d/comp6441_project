import re
from datetime import datetime

LOG_FILE = "sample_access.log"

pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<path>[^\s]+)\s+HTTP/\d\.\d"\s+(?P<status>\d+)\s+(?P<size>\d+)\s+"[^"]*"\s+"(?P<agent>[^"]*)"'
)

def parse_access_log_line(line):
    match = pattern.match(line)
    if not match:
        return None
    data = match.groupdict()
    data['timestamp'] = datetime.strptime(data['timestamp'], "%d/%b/%Y:%H:%M:%S %z")
    return data

def parse_access_log_file(filepath):
    entries = []
    with open(filepath, "r") as f:
        for line in f:
            result = parse_access_log_line(line.strip())
            if result:
                entries.append(result)
    return entries

