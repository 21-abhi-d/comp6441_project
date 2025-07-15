import os
import sys

# Add subfolder path for detector imports
sys.path.append(os.path.join(os.path.dirname(__file__), "detectors"))

from detectors.bf_detector import detect_brute_force
from detectors.web_attack_detector import detect_web_attacks

# Import exporter utilities
from utils.exporter import save_to_csv, save_to_json

# Ensure output directory exists
os.makedirs("output", exist_ok=True)

# Detect threats
auth_suspects = detect_brute_force(folder_path="auth_log_files")
access_suspects = detect_web_attacks(folder_path="access_log_files")

# Print Brute-force Results
print("\nBrute-force Detection Results:")
if not auth_suspects:
    print(" - No suspicious IPs detected.")
else:
    for ip, count in auth_suspects:
        print(f" - {ip} ({count} failed attempts)")

# Print Web Attack Results
print("\nWeb Attack Detection Results:")
if not access_suspects:
    print(" - No suspicious entries found.")
else:
    for ip, reason, path in access_suspects:
        print(f" - {ip} triggered [{reason}] on path: {path}")




# --- Export Section ---

# Format detection results as dicts
bf_export = [{"ip": ip, "failed_attempts": count} for ip, count in auth_suspects]
wa_export = [{"ip": ip, "reason": reason, "path": path} for ip, reason, path in access_suspects]

# Save to CSV & JSON if there's data
if bf_export:
    save_to_csv(bf_export, "output/brute_force.csv", bf_export[0].keys())
    save_to_json(bf_export, "output/brute_force.json")

if wa_export:
    save_to_csv(wa_export, "output/web_attacks.csv", wa_export[0].keys())
    save_to_json(wa_export, "output/web_attacks.json")
