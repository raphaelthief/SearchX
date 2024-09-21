import requests

from colorama import init, Fore, Style

init()  # Init colorama for colored text in terminal


def subreponse(domain):
    url = f"https://leakix.net/api/subdomains/{domain}"
    response = requests.get(url)

    if response.status_code == 200:
        subdomains = response.json()
        
        if subdomains:  
            print(f"\n{Fore.YELLOW}[!] Subdomains")
            for entry in subdomains:
                print(f"{Fore.GREEN}[+] {Fore.YELLOW}Subdomain : {Fore.GREEN}{entry['subdomain']}")
                print(f"{Fore.GREEN}[+] {Fore.YELLOW}Distinct IPs : {Fore.GREEN}{entry['distinct_ips']}")
                print(f"{Fore.GREEN}[+] {Fore.YELLOW}Last Seen : {Fore.GREEN}{entry['last_seen']}\n")
        else:
            pass
    else:
        pass
