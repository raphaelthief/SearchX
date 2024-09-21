import requests, urllib3, json
from tabulate import tabulate
from requests.exceptions import ConnectionError, RequestException
# colorama
from colorama import init, Fore, Style

init() # Init colorama

# https://www.proxynova.com/
def proxynova(leak):
    url = f"https://api.proxynova.com/comb?query={leak}"
    headers = {'User-Agent': 'curl'}
    session = requests.session()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    response = session.get(url, headers=headers, verify=False)

    if response.status_code == 200:
        data = json.loads(response.text)
        total_results = data.get("count", 0)
        print((f"\n{Fore.GREEN}[+] Found {Fore.YELLOW}{total_results} {Fore.GREEN}results in COMB db (https://www.proxynova.com/){Fore.GREEN}\n\n"), end='')

        lines = data.get("lines")
        return lines
    else:
        print(f"{Fore.RED}Error from ProxyNova : {Fore.YELLOW}{response.status_code}{Fore.GREEN}\n\n")
        return []

#results
def print_proxynova(results):
    headers = ["Username or Domain", "Password"]
    table_data = []
                
    for line in results:
        parts = line.split(":")
        if len(parts) == 2:
            username_domain, password = parts
            table_data.append([username_domain, password])
    print(tabulate(table_data, headers, showindex="never"))
    print("")


def proxynova1(target):
    try:
        results = proxynova(target)
            
        if not results:
            print(f"{Fore.RED} No leaks for {args.comb}{Fore.GREEN}\n\n")
        else:
            print_proxynova(results)
                
    except ConnectionError:
        print(f"{Fore.RED}Connexion error ...{Fore.GREEN}\n\n")
