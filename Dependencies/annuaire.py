import urllib.parse, requests
from bs4 import BeautifulSoup

# colorama
from colorama import init, Fore, Style

init() # Init colorama

def annu118000(who, where):
    res = []
    
    qui_encoded = urllib.parse.quote(who)
    ou_encoded = urllib.parse.quote(where)
    
    req = requests.get(f'https://www.118000.fr/search?label={where}&who={who}',
                       headers={'User-Agent': 'Mozilla/5.0'})

    h = BeautifulSoup(req.text, 'lxml')
    for p in h.find_all(class_="card"):
        try:
            nom = p.find("h2", class_="name").text.strip()
            adresse_bloc = p.find("div", class_="address")
            adresse = adresse_bloc.get_text(separator=" ", strip=True) if adresse_bloc else "Adresse non disponible"
            parts = adresse.split()
            cp = parts[-2] if len(parts) >= 2 else ""
            ville = parts[-1] if len(parts) >= 2 else ""
            res.append(dict(
                Nom=nom,
                Adresse=adresse,
                CodePostal=cp,
                Ville=ville,
                Telephone="Numéro masqué ou protégé",
                Source=f'https://www.118000.fr/search?label={ou_encoded}&who={qui_encoded}'
            ))
        except Exception as e:
            print(f"[ERREUR] {e}")
            continue
    return res


def annuaire_search(lastname, name, where):
    who = f"{lastname} {name}"
    results = annu118000(who, where)

    if results:
        for result in results:
            print(f"{Fore.YELLOW}Name    : {Fore.GREEN}{result['Nom']}")
            print(f"{Fore.YELLOW}Adresse : {Fore.GREEN}{result['Adresse']}")
            print(f"{Fore.YELLOW}CP      : {Fore.GREEN}{result['CodePostal']}")
            print(f"{Fore.YELLOW}City    : {Fore.GREEN}{result['Ville']}")
            print(f"{Fore.YELLOW}Phone   : {Fore.GREEN}{result['Telephone']}")
            print(f"{Fore.YELLOW}Source  : {Fore.GREEN}{result['Source']}")
            print("-"*50) 
    else:
        print(f"{Fore.RED}[-] {Fore.YELLOW}No result found ...")
    print("")