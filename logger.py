import json
import csv
import os
from datetime import datetime
import yaml

def log_to_file(data, threat):
    # Load config to see preferred format
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)
    
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": data["src_ip"],
        "dst_port": data["dst_port"],
        "protocol": data["protocol"],
        "threat_type": threat
    }

    if config['logging']['export_format'] == "json":
        with open("alerts.json", "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    else:
        file_exists = os.path.isfile("alerts.csv")
        with open("alerts.csv", "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=log_entry.keys())
            if not file_exists:
                writer.writeheader()
            writer.writerow(log_entry)