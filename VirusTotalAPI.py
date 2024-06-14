import requests
import json

# Your VirusTotal API key

API_KEY = 'YOUR_API_KEY'
FILE_PATH = 'your-file-path -> .txt'

def get_ip_report(ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {
        'x-apikey': API_KEY
    }
    response = requests.get(url, headers=headers)
    return response.json()

def print_ip_report(ip_report):
    data = ip_report.get('data', {})
    attributes = data.get('attributes', {})
    
    ip = data.get('id', 'N/A')
    country = attributes.get('country', 'N/A')
    score = attributes.get('last_analysis_stats', {}).get('malicious', 'N/A')
    description = 'N/A'
    if 'crowdsourced_context' in attributes and attributes['crowdsourced_context']:
        description = attributes['crowdsourced_context'][0].get('details', 'N/A')

    print(f"IP: {ip}")
    print(f"Score: {score}")
    print(f"Description: {description}")
    print(f"Country: {country}")
    print("=" * 40)

def main():
    with open(FILE_PATH, 'r') as file:
        ips = file.readlines()
    
    for ip in ips:
        ip = ip.strip()
        print(f"Analyzing IP: {ip}")
        ip_report = get_ip_report(ip)
        print_ip_report(ip_report)

if __name__ == "__main__":
    main()

def get_ip_report(ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {
        'x-apikey': API_KEY
    }
    response = requests.get(url, headers=headers)
    return response.json()

def print_ip_report(ip_report):
    data = ip_report.get('data', {})
    attributes = data.get('attributes', {})
    
    ip = data.get('id', 'N/A')
    country = attributes.get('country', 'N/A')
    analysis_stats = attributes.get('last_analysis_stats', {})
    malicious_count = analysis_stats.get('malicious', 'N/A')
    total_count = sum(analysis_stats.values())
    description = 'N/A'
    
    if 'crowdsourced_context' in attributes and attributes['crowdsourced_context']:
        description = attributes['crowdsourced_context'][0].get('details', 'N/A')

    print(f"IP: {ip}")
    print(f"Antivirus flagged this IoC as malicious: {malicious_count} of {total_count}")
    print(f"Description: {description}")
    print(f"Country: {country}")
    print("=" * 40)

def main():
    with open(FILE_PATH, 'r') as file:
        ips = file.readlines()
    
    for ip in ips:
        ip = ip.strip()
        print(f"Analyzing IP: {ip}")
        ip_report = get_ip_report(ip)
        print_ip_report(ip_report)

if __name__ == "__main__":
    main()
