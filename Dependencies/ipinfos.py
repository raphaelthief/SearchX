import requests
import json

# colorama
from colorama import init, Fore, Style

init() # Init colorama


def ipinfo(ip):
        
    url = f"https://ipinfo.io/widget/demo/{ip}"
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()

        ip_address = data.get("data", {}).get("ip")
        city = data.get("data", {}).get("city")
        region = data.get("data", {}).get("region")
        country = data.get("data", {}).get("country")
        loc = data.get("data", {}).get("loc")
        org = data.get("data", {}).get("org")
        postal = data.get("data", {}).get("postal")
        timezone = data.get("data", {}).get("timezone")
        abuse_info = data.get("data", {}).get("abuse", {})

        print(f"\n{Fore.YELLOW}[!] IP infos")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}IP Address              : {Fore.GREEN}{ip_address}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}City                    : {Fore.GREEN}{city}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Region                  : {Fore.GREEN}{region}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Country                 : {Fore.GREEN}{country}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Location (lat, long)    : {Fore.GREEN}{loc}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Organization            : {Fore.GREEN}{org}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Postal Code             : {Fore.GREEN}{postal}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Timezone                : {Fore.GREEN}{timezone}")
        
        print(f"\n{Fore.YELLOW}[!] Abuse Information")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Address                 : {Fore.GREEN}{abuse_info.get('address')}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Country                 : {Fore.GREEN}{abuse_info.get('country')}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Email                   : {Fore.GREEN}{abuse_info.get('email')}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Name                    : {Fore.GREEN}{abuse_info.get('name')}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Phone                   : {Fore.GREEN}{abuse_info.get('phone')}")
    else:
        pass

