import csv
from datetime import datetime

def log_to_file(data, threat):
    if threat == "NORMAL": return # Only log suspicious stuff or keep it clean
    
    log_entry = [datetime.now(), data["src_ip"], data["dst_ip"], data["protocol"], threat]
    
    with open("alerts.csv", "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(log_entry)