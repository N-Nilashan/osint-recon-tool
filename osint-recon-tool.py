import argparse
from colorama import init, Fore, Style
import whois
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
import requests
import time
import sys
from config import VIRUSTOTAL_API_KEY

# initialize colorama so colored text works in terminal
init(autoreset=True)

# argument parser to accept domain from CLI
parser = argparse.ArgumentParser(description="Osint Recon Tool")
parser.add_argument('-d','--domain',required=True,help="Enter the domain link")
args = parser.parse_args()

# open markdown report file and redirect all normal prints into it
md_file = open("report.md", "w", encoding="utf-8")
sys.stdout = md_file

def get_whois(domain):
    try:
        # fetch WHOIS info for the domain
        detail = whois.whois(domain)

        # nicely formatted markdown section
        print("## 🌐 WHOIS Information\n")
        print(f"- **Domain Name:** {detail.domain_name}")
        print(f"- **Registrar:** {detail.registrar}")
        print(f"- **Creation Date:** {detail.creation_date}")
        print(f"- **Expiration Date:** {detail.expiration_date}")
        print(f"- **Last Updated:** {detail.updated_date}")
        print(f"- **Name Servers:** {detail.name_servers}")
        print(f"- **Registrant Country:** {detail.country}\n")

    except Exception as e:
        # catch any WHOIS lookup issues
        print(f"❌ WHOIS error: {e}\n")

def get_dns_records(domain):
    print("## 📡 DNS Records\n")

    # A records
    try:
        address = dns.resolver.resolve(domain,'A')
        print("### A Records")
        for rdata in address:
            print(f"- {rdata.address}")
    except Exception as e:
        print(f"❌ A record error: {e}")

    # MX records
    try:
        mail = dns.resolver.resolve(domain, 'MX')
        print("\n### MX Records")
        for rdata in mail:
            print(f"- {rdata.exchange}")
    except Exception as e:
        print(f"❌ MX record error: {e}")

    # TXT records
    try:
        secret_text = dns.resolver.resolve(domain, 'TXT')
        print("\n### TXT Records")
        for rdata in secret_text:
            print(f"- {rdata.strings}")
    except Exception as e:
        print(f"❌ TXT record error: {e}")

    # NS records
    try:
        server = dns.resolver.resolve(domain, 'NS')
        print("\n### NS Records")
        for rdata in server:
            print(f"- {rdata.target}")
    except Exception as e:
        print(f"❌ NS record error: {e}")

    print("")

def check_subdomains(subdomain):
    try:
        # try resolving subdomain to see if it exists
        ip_address = dns.resolver.resolve(subdomain,'A')
        for rdata in ip_address:
            print(f"- **{subdomain}** → {rdata.address}")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        # silently ignore non-existing subdomains
        pass
    except Exception as e:
        print(f"- Error checking {subdomain}: {e}")

def enumerate_subdomains(domain):
    try:
        print("## 🔎 Subdomain Enumeration\n")

        # load wordlist
        with open("subdomains_wordlist.txt", 'r') as f:
            words = [line.strip() for line in f]

        # use threads for faster enumeration
        with ThreadPoolExecutor(max_workers=30) as executor:
            for word in words:
                subdomain = f"{word}.{domain}"
                executor.submit(check_subdomains,subdomain)

        print("")
    except Exception as e:
        # catch file read or threading issues
        print(f"❌ Subdomain enumeration error: {e}\n")

def check_reputation(domain):
    try:
        print("## 🛡️ Reputation Analysis\n")

        # headers with API key
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "User-Agent": "Mozilla/5.0"
        }

        # submit URL to VirusTotal for scanning
        post_response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": domain}
        )
        post_data = post_response.json()
        analysis_id = post_data["data"]["id"]
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        # wait a bit so analysis completes
        time.sleep(10)

        # fetch analysis result
        get_response = requests.get(analysis_url, headers={"x-apikey": VIRUSTOTAL_API_KEY})
        result_data = get_response.json()

        # print summary stats
        stats = result_data.get("data", {}).get("attributes", {}).get("stats", {})
        print("### Detection Stats")
        for key, value in stats.items():
            print(f"- **{key.capitalize()}**: {value}")

        # print per-engine results
        print("\n### Engine Results")
        results = result_data.get("data", {}).get("attributes", {}).get("results", {})
        for engine, info in results.items():
            print(f"- {engine}: {info['category']}")

        print("")
    except Exception as e:
        # handle API or parsing issues
        print(f"❌ Reputation check error: {e}\n")

args.domain = str(args.domain)

# colored terminal progress (stderr so it doesn’t go into markdown file)
sys.stderr.write(Fore.CYAN + f"[+] Starting recon on {args.domain}...\n")

# markdown report header
print(f"# 🧠 Recon Report for `{args.domain}`\n")
print(f"_Generated automatically by OSINT Recon Tool_\n\n---\n")

# step-by-step progress logs
sys.stderr.write(Fore.YELLOW + "[+] Fetching WHOIS data...\n")
get_whois(args.domain)

sys.stderr.write(Fore.YELLOW + "[+] Fetching DNS records...\n")
get_dns_records(args.domain)

sys.stderr.write(Fore.YELLOW + "[+] Enumerating subdomains...\n")
#enumerate_subdomains(args.domain)

sys.stderr.write(Fore.YELLOW + "[+] Checking reputation via VirusTotal...\n")
check_reputation(args.domain)

sys.stderr.write(Fore.GREEN + "[✔] Recon completed. Report saved to report.md\n")

# close markdown file after everything finishes
md_file.close()