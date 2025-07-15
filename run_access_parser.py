from access_log_parser import parse_access_log_folder
from utils.exporter import save_to_csv, save_to_json

folder = "access_log_files"
entries = parse_access_log_folder(folder)

print(f"Parsed {len(entries)} entries from folder '{folder}':\n")
for entry in entries[:10]:
    print(entry)
    
# Save results
if entries:
    save_to_csv(entries, "output/parsed_access.csv", entries[0].keys())
    save_to_json(entries, "output/parsed_access.json")
