import requests
from bs4 import BeautifulSoup

# colorama
from colorama import init, Fore, Style

init() # Init colorama


def get_ip_info(ip):
    url = f"https://iknowwhatyoudownload.com/en/peer/?ip={ip}"
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
    torrent_table = soup.find('table', {'class': 'table-striped'})
    
    if not torrent_table:
        return None

    torrents = []
    for row in torrent_table.find_all('tr')[1:]:  
        columns = row.find_all('td')
        if len(columns) == 5:
            first_seen = columns[0].get_text(strip=True)
            last_seen = columns[1].get_text(strip=True)
            category = columns[2].get_text(strip=True)
            title = columns[3].get_text(strip=True)
            size = columns[4].get_text(strip=True)


            print(f"{Fore.GREEN}[+] {Fore.YELLOW}First_seen : {Fore.GREEN}{first_seen}")
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Last_seen  : {Fore.GREEN}{last_seen}")
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Category   : {Fore.GREEN}{category}")
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Title      : {Fore.GREEN}{title}")
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Size       : {Fore.GREEN}{size}")
            print("")

    return torrents
    
def torrents(ip):
    
    torrentX = get_ip_info(ip)

    if torrentX:
        for torrent in torrentX:
            print(f"{Fore.YELLOW}[!] Torrent downloaded")
            print(torrent)