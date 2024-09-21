import hashlib, requests, urllib3, json

# colorama
from colorama import init, Fore, Style

init() # Init colorama

def sha1_convert(target):
    byte_W = target.encode('utf-8')
    sha1_hash = hashlib.sha1()
    sha1_hash.update(byte_W)
    return sha1_hash.hexdigest()


def passwordtest(target):
   
    HASH = sha1_convert(target)
   
    url = f"https://api.breachdirectory.org/passsearch?hash={HASH}"
    headers = {'User-Agent': 'curl'}
    session = requests.session()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print(f"{Fore.GREEN}\n[!] Searching for : {Fore.YELLOW}{target}")

    response = session.get(url, headers=headers, verify=False)

    if response.status_code == 200:
        data = json.loads(response.text)
        total_results = data.get("count", 0)
        print((f"{Fore.GREEN}[+] Found {Fore.YELLOW}{total_results} {Fore.GREEN}leaked passwords in breachdirectory db{Fore.GREEN}\n\n"), end='')

    else:
        print(f"{Fore.RED}Error from breachdirectory : {Fore.YELLOW}{response.status_code}{Fore.GREEN}\n\n")
        return []

