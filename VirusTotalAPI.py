import requests
import json
import time

# Your VirusTotal API key
API_KEY = 'your_Virustotal'

# VirusTotal API URLs
IP_SCAN_URL = 'https://www.virustotal.com/api/v3/ip_addresses/{}'

# Function to get the report of an IP address from VirusTotal
def get_ip_report(ip_address):
    headers = {
        'x-apikey': API_KEY
    }
    response = requests.get(IP_SCAN_URL.format(ip_address), headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code}")
        print(response.json())
        return None

# Main function
def main():
    file_path = r'your_path_file -> malicious-ip.txt'  # Change this to the path of the file you want to scan

    with open(file_path, 'r') as file:
        ip_addresses = file.readlines()

    for ip in ip_addresses:
        ip = ip.strip()
        if ip:
            print(f"Analyzing IP: {ip}")
            report = get_ip_report(ip)
            if report:
                print(json.dumps(report, indent=4))
            else:
                print(f"Failed to retrieve the report for IP: {ip}")
            time.sleep(15)  # Respect the API rate limit

if __name__ == '__main__':
    main()
