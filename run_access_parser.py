from access_log_parser import parse_access_log_folder

folder = "access_log_files"
entries = parse_access_log_folder(folder)

print(f"Parsed {len(entries)} entries from folder '{folder}':\n")
for entry in entries[:10]:
    print(entry)
