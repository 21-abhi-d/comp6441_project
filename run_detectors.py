import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "detectors"))

from detectors.bf_detector import detect_brute_force
from detectors.web_attack_detector import detect_web_attacks

auth_suspects = detect_brute_force("auth_log_files")
access_suspects = detect_web_attacks("access_log_files")

print("\nBrute-force Detection Results:")
if not auth_suspects:
    print(" - No suspicious IPs detected.")
else:
    for ip, count in auth_suspects:
        print(f" - {ip} ({count} failed attempts)")

print("\nWeb Attack Detection Results:")
if not access_suspects:
    print(" - No suspicious entries found.")
else:
    for ip, reason, path in access_suspects:
        print(f" - {ip} triggered [{reason}] on path: {path}")
