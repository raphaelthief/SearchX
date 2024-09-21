import requests

# colorama
from colorama import init, Fore, Style

init() # Init colorama


def leackcheck(email):

    url = f"https://leakcheck.io/api/public?check={email}"
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()  
        if data['success']:
            
            print(f"\n{Fore.YELLOW}[!] leakcheck db")
            print(f"{Fore.YELLOW}[?] Source : https://leakcheck.io")
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Datas found : {Fore.GREEN}{data['found']}")
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Extracted :{Fore.GREEN} ", ", ".join(data['fields']))
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Sources :{Fore.GREEN}")
            for source in data['sources']:
                print(f" {Fore.YELLOW}--> {Fore.GREEN}{source['name']} (Date : {source['date']})")
        else:
            pass
    else:
        pass
