import requests, json

from colorama import init, Fore, Style
from datetime import datetime

init()  # Init colorama for colored text in terminal


def subreponse(domain):
    url = f"https://leakix.net/api/subdomains/{domain}"
    response = requests.get(url)

    if response.status_code == 200:
        subdomains = response.json()
        
        if subdomains:  
            print(f"\n{Fore.YELLOW}[!] Subdomains")
            print(f"{Fore.YELLOW}[?] Source : {Fore.GREEN}leakix.net{Fore.YELLOW}")
            print("-" * 50)
            for entry in subdomains:
                print(f"{Fore.GREEN}[+] {Fore.YELLOW}Subdomain    : {Fore.CYAN}{entry['subdomain']}")
                print(f"{Fore.GREEN}[+] {Fore.YELLOW}Distinct IPs : {Fore.GREEN}{entry['distinct_ips']}")
                print(f"{Fore.GREEN}[+] {Fore.YELLOW}Last Seen    : {Fore.GREEN}{entry['last_seen']}{Fore.YELLOW}")
                print(f"-" * 50)

    subreponse2(domain)
    

def subreponse2(domain):
    filtered_results = {}

    url = f"https://crt.sh/json?q={domain}"
    response = requests.get(url)

    if response.status_code == 200:
        certs = response.json() 
        
        for cert in certs:
            common_name = cert["common_name"]
            entry_date = cert["entry_timestamp"].split("T")[0]
            
            if (
                common_name not in filtered_results or
                entry_date > filtered_results[common_name]["entry_timestamp"].split("T")[0]
            ):
                filtered_results[common_name] = {
                    "common_name": common_name,
                    "entry_timestamp": cert["entry_timestamp"],
                    "id": cert["id"]
                }
                
        filtered_list = list(filtered_results.values())
        print(f"\n{Fore.YELLOW}[!] Subdomains")
        print(f"{Fore.YELLOW}[?] Source : {Fore.GREEN}crt.sh{Fore.YELLOW}")
        print("-" * 50)
        
        for cert in filtered_list:
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Name       : {Fore.CYAN}{cert['common_name']}")
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Entry time : {Fore.GREEN}{cert['entry_timestamp']}")
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}More infos : {Fore.GREEN}https://crt.sh/?id={cert['id']}{Fore.YELLOW}")
            print("-" * 50)
