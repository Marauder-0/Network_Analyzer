import socket

target = "YOUR IP ADDRESS HERE"
print(f"Starting fake scan on {target}...")

for port in range(1, 100):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.01) # Fast timeout to trigger the 'threshold'
    result = s.connect_ex((target, port))
    if result == 0:
        print(f"Port {port} is open")
    s.close()

print("Scan complete.")