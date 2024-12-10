import requests, json

from colorama import init, Fore, Style
from datetime import datetime

init()  # Init colorama for colored text in terminal


import requests
from colorama import Fore

def fetch_json(url):
    """Performs a GET request and returns the JSON data or an error message."""
    try:
        response = requests.get(url)
        response.raise_for_status()  # Checks for HTTP errors
        try:
            return response.json()  # Returns the JSON response
        except requests.exceptions.JSONDecodeError:
            print(f"{Fore.RED}[!] Error : Invalid JSON response from {url}")
            print(f"{Fore.RED}[!] Raw response content : {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Request error to {url} : {e}")
        return None

def subreponse(domain):
    """Récupère et affiche les sous-domaines depuis leakix.net."""
    url = f"https://leakix.net/api/subdomains/{domain}"
    subdomains = fetch_json(url)

    if subdomains:
        print(f"\n{Fore.YELLOW}[!] Subdomains")
        print(f"{Fore.YELLOW}[?] Source : {Fore.GREEN}leakix.net{Fore.YELLOW}")
        print("-" * 50)
        for entry in subdomains:
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Subdomain    : {Fore.CYAN}{entry.get('subdomain', 'N/A')}")
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Distinct IPs : {Fore.GREEN}{entry.get('distinct_ips', 'N/A')}")
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Last Seen    : {Fore.GREEN}{entry.get('last_seen', 'N/A')}{Fore.YELLOW}")
            print(f"-" * 50)

    # Appelle la seconde fonction pour obtenir les sous-domaines de crt.sh
    subreponse2(domain)

def subreponse2(domain):
    """Récupère et affiche les sous-domaines depuis crt.sh."""
    url = f"https://crt.sh/json?q={domain}"
    certs = fetch_json(url)

    if certs:
        filtered_results = {}
        for cert in certs:
            common_name = cert.get("common_name")
            entry_date = cert.get("entry_timestamp", "").split("T")[0]

            if common_name and entry_date:  # Vérifiez que les données sont présentes
                if (
                    common_name not in filtered_results or
                    entry_date > filtered_results[common_name]["entry_timestamp"].split("T")[0]
                ):
                    filtered_results[common_name] = {
                        "common_name": common_name,
                        "entry_timestamp": cert.get("entry_timestamp", "N/A"),
                        "id": cert.get("id", "N/A")
                    }

        # Affichez les résultats filtrés
        filtered_list = list(filtered_results.values())
        if not filtered_list:
            print(f"{Fore.YELLOW}[!] Aucun certificat trouvé pour le domaine {domain}.")
            return

        print(f"\n{Fore.YELLOW}[!] Subdomains")
        print(f"{Fore.YELLOW}[?] Source : {Fore.GREEN}crt.sh{Fore.YELLOW}")
        print("-" * 50)
        for cert in filtered_list:
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Name       : {Fore.CYAN}{cert['common_name']}")
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Entry time : {Fore.GREEN}{cert['entry_timestamp']}")
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}More infos : {Fore.GREEN}https://crt.sh/?id={cert['id']}{Fore.YELLOW}")
            print("-" * 50)
