import re
import csv
from collections import Counter

# Configure the threshold for failed login attempts
FAILED_LOGIN_THRESHOLD = 10

# Parse the log file
log_file_path = r"C:\Users\lokel\OneDrive\Desktop\sample.log"  # Update with the actual file path
output_file_path = "log_analysis_results.csv"

# Data containers
ip_requests = Counter()
endpoint_accesses = Counter()
failed_login_attempts = Counter()

# Regular expressions for parsing
ip_regex = r"(\d+\.\d+\.\d+\.\d+)"
endpoint_regex = r"\"(?:GET|POST) (/\S*)"
status_code_regex = r"\" (\d{3}) "
failed_login_message = "Invalid credentials"

with open(log_file_path, "r") as log_file:
    for line in log_file:
        # Extract IP address
        ip_match = re.search(ip_regex, line)
        if ip_match:
            ip = ip_match.group(1)
            ip_requests[ip] += 1

        # Extract endpoint
        endpoint_match = re.search(endpoint_regex, line)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            endpoint_accesses[endpoint] += 1

        # Detect failed login attempts
        if "401" in line or failed_login_message in line:
            if ip_match:
                failed_login_attempts[ip] += 1

# Sort results
ip_requests = ip_requests.most_common()
endpoint_accesses = endpoint_accesses.most_common()
suspicious_ips = [(ip, count) for ip, count in failed_login_attempts.items() if count > FAILED_LOGIN_THRESHOLD]

# Display results
print("IP Address Requests:")
for ip, count in ip_requests:
    print(f"{ip:<20} {count}")

if endpoint_accesses:
    most_accessed_endpoint, access_count = endpoint_accesses[0]
    print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed_endpoint} (Accessed {access_count} times)")

print("\nSuspicious Activity Detected:")
if suspicious_ips:
    for ip, count in suspicious_ips:
        print(f"{ip:<20} {count}")
else:
    print("No suspicious activity detected.")

# Save results to CSV
with open(output_file_path, "w", newline="") as csv_file:
    writer = csv.writer(csv_file)

    # Write IP requests
    writer.writerow(["IP Address", "Request Count"])
    writer.writerows(ip_requests)

    # Write most accessed endpoint
    writer.writerow([])
    writer.writerow(["Endpoint", "Access Count"])
    if endpoint_accesses:
        writer.writerow([most_accessed_endpoint, access_count])

    # Write suspicious activity
    writer.writerow([])
    writer.writerow(["IP Address", "Failed Login Count"])
    writer.writerows(suspicious_ips)

print(f"\nResults saved to {output_file_path}")
