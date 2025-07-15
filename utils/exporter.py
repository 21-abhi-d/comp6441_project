import csv
import json
import os

def save_to_csv(data, filename, fieldnames):
    with open(filename, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

def save_to_json(data, filename):
    with open(filename, "w") as f:
        json.dump(data, f, default=str, indent=4)
