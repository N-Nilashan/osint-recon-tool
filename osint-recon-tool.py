import argparse
from colorama import init, Fore, Back, Style
import whois
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
import requests
import time
from config import VIRUSTOTAL_API_KEY

# Initialize colorama for colored console output
init(autoreset=True)

parser = argparse.ArgumentParser(description="Osint Recon Tool")
parser.add_argument('-d','--domain',required=True,help="Enter the domain link")

args = parser.parse_args()

def get_whois(domain):
    try:
        detail = whois.whois(domain)
        print("Domain Name: ",detail.domain_name)
        print("Registrar Name: ",detail.registrar)
        print("Creation Date: ",detail.creation_date)
        print("Expiration date: ", detail.expiration_date)
        print("Last updated date: ",detail.updated_date)
        print("Name servers: ",detail.name_servers)
        print("Registrant country: ",detail.country)
    except Exception as e:
        print("WHOIS error:", e)

def get_dns_records(domain):
    try:
        address = dns.resolver.resolve(domain,'A')
        mail = dns.resolver.resolve(domain, 'MX')
        secret_text = dns.resolver.resolve(domain, 'TXT')
        server = dns.resolver.resolve(domain, 'NS')

        for rdata in address:
            print(f"IP Address of {domain}: ",rdata.address)
        for rdata in mail:
            print("mail servers: ",rdata.exchange)
        for rdata in secret_text:
            print("TXT records: ",rdata.strings)
        for rdata in server:
            print("servers control the domain: ",rdata.target)
    except Exception as e:
        print("DNS records error:", e)

def check_subdomains(subdomain):
    try:
        ip_address = dns.resolver.resolve(subdomain,'A')
        for rdata in ip_address:
            print(f"{subdomain} → {rdata.address}")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        pass
    except Exception as e:
        print(f"Subdomain check error ({subdomain}):", e)

def enumerate_subdomains(domain):
    try:
        with open("subdomains_wordlist.txt", 'r') as f:
            words = [line.strip() for line in f]

        with ThreadPoolExecutor(max_workers=30) as executor:
            for word in words:
                subdomain = f"{word}.{domain}"
                executor.submit(check_subdomains,subdomain)
    except Exception as e:
        print("Subdomain enumeration error:", e)

def check_reputation(domain):
    try:
        url_to_check = domain
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "User-Agent": "Mozilla/5.0 (Linux; Android 13; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36"
        }
        post_response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data = {"url": url_to_check}
        )
        post_data = post_response.json()
        analysis_id = post_data["data"]["id"]
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        time.sleep(10)

        get_response = requests.get(analysis_url, headers={"x-apikey": VIRUSTOTAL_API_KEY})
        result_data = get_response.json()

        stats = result_data.get("data", {}).get("attributes", {}).get("stats", {})
        print("Reputation stats:", stats)

        results = result_data.get("data", {}).get("attributes", {}).get("results", {})
        for engine, info in results.items():
            print(f"{engine}: {info['category']}")
    except Exception as e:
        print("Reputation check error:", e)

args.domain = str(args.domain)
print(f"Starting recon on {args.domain}...")
print(f"Getting {args.domain} WHOIS data... ")
get_whois(args.domain)
print("")
print(f"Getting {args.domain} DNS Records...")
get_dns_records(args.domain)
print("")
print(f"Getting Subdomain Enumeration of {args.domain}")
enumerate_subdomains(args.domain)
print("")
print("Checking reputation...")
check_reputation(args.domain)