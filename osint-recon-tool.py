import argparse
from colorama import init, Fore, Back, Style
import whois
import dns.resolver

# Initialize colorama for colored console output
init(autoreset=True)

parser = argparse.ArgumentParser(description="Osint Recon Tool")
parser.add_argument('-d','--domain',required=True,help="Enter the domain link")

args = parser.parse_args()

def get_whois(domain):
    detail = whois.whois(domain)
    print("Domain Name: ",detail.domain_name)
    print("Registrar Name: ",detail.registrar)
    print("Creation Date: ",detail.creation_date)
    print("Expiration date: ", detail.expiration_date)
    print("Last updated date: ",detail.updated_date)
    print("Name servers: ",detail.name_servers)
    print("Registrant country: ",detail.country)

def get_dns_records(domain):
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


if args.domain:
    args.domain = str(args.domain)
    print(f"Starting recon on {args.domain}...")
    print(f"Getting {args.domain} WHOIS data... ")
    get_whois(args.domain)
    print("")
    print(f"Getting {args.domain} DNS Records...")
    get_dns_records(args.domain)




