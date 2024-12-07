# Log File Analysis Script

## What is this Project About?

This Python script helps you analyze server log files to gain useful insights about the traffic on a website or server. The script processes the log file and shows important information like:

1. **How many requests each IP address made**: It counts the number of times each IP address accessed the server.
2. **Which page was visited the most**: It tells you the most frequently accessed page or endpoint.
3. **Suspicious activity detection**: It helps identify IP addresses that made too many failed login attempts, which could indicate malicious activity.

After processing the log file, the results are shown in your terminal and saved in a CSV file for easy review.

## Key Features

- **Requests per IP**: It shows how many requests were made by each IP address.
- **Most Accessed Endpoint**: It identifies the page (endpoint) that received the most visits.
- **Suspicious Activity**: It detects IP addresses with a high number of failed login attempts.

## How to Use

1. **Clone the Repository**:
   First, get a copy of this project:
   ```bash
   git clone https://github.com/Navaritha/log-file-analysis.git
   cd log-file-analysis
2. Install the Required Libraries: Make sure you have the required libraries by installing them:

pip install -r requirements.txt
3.Add Your Log File: Place your log file (e.g., sample.log.txt) in the project folder, or you can update the script to use a different log file location.
4.Run the Script: Run the Python script to analyze your log file:

python log_analysis.py
The script will display the results in the terminal and save them in a file called log_analysis_results.csv.

Output
Terminal Output:
You will see something like this in the terminal:

Requests per IP:
192.168.1.1 - 5 requests
203.0.113.5 - 3 requests
Most Accessed Endpoint: /login - 15 times
Suspicious Activity Detected: 
IP Address            Failed Login Attempts
192.168.1.100         10
203.0.113.5           8

CSV File:
The results will also be saved in a CSV file, log_analysis_results.csv, with the following structure:

Requests per IP: Shows the IP address and how many requests it made.
Most Accessed Endpoint: Shows which endpoint (page) was accessed the most.
Suspicious Activity: Lists the IP addresses with multiple failed login attempts.
