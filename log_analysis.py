import re
from collections import defaultdict

# Initialize dictionaries to store counts
ip_request_count = defaultdict(int)
endpoint_access_count = defaultdict(int)
failed_login_attempts = defaultdict(int)

# Regular expression pattern to match log entries
log_pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[\S+ \S+\] "(?P<method>\S+) (?P<endpoint>\S+) \S+" (?P<status_code>\d+)'

# Function to parse the log file and extract relevant data
def parse_log_file(log_file):
    with open(log_file, 'r') as file:
        for line in file:
            match = re.match(log_pattern, line)
            if match:
                ip = match.group('ip')
                method = match.group('method')
                endpoint = match.group('endpoint')
                status_code = int(match.group('status_code'))
                
                # Count total requests for the IP address
                ip_request_count[ip] += 1
                
                # Count access to each endpoint
                endpoint_access_count[endpoint] += 1
                
                # Detect failed login attempts (status 401 on /login)
                if method == 'POST' and endpoint == '/login' and status_code == 401:
                    failed_login_attempts[ip] += 1

# Function to display the analysis results
def display_analysis_results():
    print("IP Address           Request Count")
    for ip, count in ip_request_count.items():
        print(f"{ip}        {count}")
    
    print("\nEndpoint           Access Count")
    for endpoint, count in endpoint_access_count.items():
        print(f"{endpoint}        {count}")
    
    print("\nSuspicious Activity Detected: IP Address           Failed Login Attempts")
    for ip, failed_count in failed_login_attempts.items():
        if failed_count >= 5:  # You can adjust this threshold as needed
            print(f"{ip}        {failed_count}")

# Main function to run the log analysis
def main():
    log_file = 'sample.log.txt'  
    parse_log_file(log_file)
    display_analysis_results()

if __name__ == '__main__':
    main()
