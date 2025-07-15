from auth_log_parser import parse_auth_log_folder
from utils.exporter import save_to_csv, save_to_json

folder = "auth_log_files"
entries = parse_auth_log_folder(folder)

print(f"Parsed {len(entries)} entries from folder '{folder}':\n")
for entry in entries[:10]:  # Print first 10 for inspection
    print(entry)

if entries:
    save_to_csv(entries, "output/parsed_auth.csv", entries[0].keys())
    save_to_json(entries, "output/parsed_auth.json")