import requests
from bs4 import BeautifulSoup

# colorama
from colorama import init, Fore, Style

init() # Init colorama


def scam(email):
  
    print(f"\n{Fore.YELLOW}[!] Email reputation")  

    url = f"https://scamsearch.io/search_report?searchoption=all&search={email}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  

    except requests.exceptions.RequestException as e:
        return None

    if not response.text:
        return None

    soup = BeautifulSoup(response.text, "html.parser")
    table = soup.find('table', {'class': 'uk-table uk-table-striped'})
    
    if not table:
        return None

    email = soup.find('td', class_='font-italic').text.strip()
    report_count = soup.find('td', text='Report Count').find_next_sibling('td').text.strip()
    latest_report = soup.find('td', text='Latest Report').find_next_sibling('td').text.strip()

    print(f"{Fore.GREEN}[+] {Fore.YELLOW}Email : {Fore.GREEN}{email}")
    print(f"{Fore.GREEN}[+] {Fore.YELLOW}Report Count : {Fore.GREEN}{report_count}")
    print(f"{Fore.GREEN}[+] {Fore.YELLOW}Latest Report : {Fore.GREEN}{latest_report}")











