import csv
from collections import defaultdict

# Initialize counters
ip_request_count = defaultdict(int)
endpoint_access_count = defaultdict(int)
suspicious_activity = defaultdict(int)

# Open and read the log file
with open('sample.log.txt', 'r') as log_file:
    for line in log_file:
        # Split log line by spaces to extract information
        parts = line.split()
        
        ip_address = parts[0]  # IP Address
        endpoint = parts[6]  # Endpoint (e.g., /home, /login)
        status_code = parts[8]  # HTTP status code
        response_time = parts[9]  # Response size (not needed here but could be useful)

        # Count requests per IP
        ip_request_count[ip_address] += 1
        
        # Count accesses to endpoints
        endpoint_access_count[endpoint] += 1
        
        # Detect suspicious activity (failed login attempts with status code 401)
        if status_code == '401':
            suspicious_activity[ip_address] += 1

# Display results in terminal
print("Requests per IP:")
print(f"{'IP Address':<20}{'Request Count':<15}")
for ip, count in ip_request_count.items():
    print(f"{ip:<20}{count:<15}")

print("\nMost Accessed Endpoint:")
print(f"{'Endpoint':<20}{'Access Count':<15}")
for endpoint, count in endpoint_access_count.items():
    print(f"{endpoint:<20}{count:<15}")

print("\nSuspicious Activity Detected:")
print(f"{'IP Address':<20}{'Failed Login Attempts':<25}")
for ip, failed_count in suspicious_activity.items():
    print(f"{ip:<20}{failed_count:<25}")

# Save results to CSV
with open('log_analysis_results.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    
    # Write headers
    writer.writerow(['Section', 'IP Address/Endpoint', 'Count'])
    
    # Write Requests per IP
    for ip, count in ip_request_count.items():
        writer.writerow(['Requests per IP', ip, count])
    
    # Write Most Accessed Endpoint
    for endpoint, count in endpoint_access_count.items():
        writer.writerow(['Most Accessed Endpoint', endpoint, count])
    
    # Write Suspicious Activity
    for ip, failed_count in suspicious_activity.items():
        writer.writerow(['Suspicious Activity', ip, failed_count])

print("\nResults have been saved to 'log_analysis_results.csv'.")
            
