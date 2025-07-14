from auth_log_parser import parse_auth_log_folder

folder = "auth_log_files"
entries = parse_auth_log_folder(folder)

print(f"Parsed {len(entries)} entries from folder '{folder}':\n")
for entry in entries[:10]:  # Print first 10 for inspection
    print(entry)
