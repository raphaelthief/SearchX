import requests, re

# colorama
from colorama import init, Fore, Style

init() # Init colorama

url = "https://whatweb.net/whatweb.php"

def parse_response(response_text):
    lignes = response_text.splitlines()
    resultats = []

    for ligne in lignes:
        infos = ligne.split(',')

        resultat = []
        for info in infos:
            info = info.replace('[', ' : ').replace(']', '')
            resultat.append(info.strip())  

        resultats.append(resultat)

    return resultats


def getwatweb(cible):
    data = {'target': cible}
    response = requests.post(url, data=data)
    response_text = response.text
    results = parse_response(response_text)
    print(f"\n{Fore.YELLOW}[!] Web technologies for {cible}")
    for resultat in results:
        for info in resultat:
            print(f"{Fore.GREEN}" + info)
        print(f'{Fore.YELLOW}-' * 50)