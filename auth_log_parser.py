import re
from datetime import datetime

LOG_FILE = "sample_auth.log"

pattern = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<status>\w+)\s+password for (?P<validity>invalid user|user)?\s*(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<port>\d+)\s+ssh2'
)

# Function to parse each line
def parse_auth_log_line(line):
    match = pattern.match(line)
    if not match:
        return None
   
    data = match.groupdict()
    CURRENT_YEAR = datetime.now().year
    date_str = f"{CURRENT_YEAR} {data['month']} {data['day']} {data['time']}"
    data['timestamp'] = datetime.strptime(date_str, "%Y %b %d %H:%M:%S")
    
    return data

def parse_log_file(filepath):
    entries = []
    with open(filepath, "r") as f:
        for line in f:
            result = parse_auth_log_line(line.strip())
            if result:
                entries.append(result)
    return entries
            


