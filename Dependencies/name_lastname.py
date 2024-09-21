import requests, bs4, re, json
from bs4 import BeautifulSoup



# colorama
from colorama import init, Fore, Style

init() # Init colorama


def namesID(name, lastname):
    facebook(name, lastname)
    copains_davant(name, lastname)
    wattpad(name,lastname)
    morts(name, lastname)
    pagesblanches(name, lastname)
    bac_brevet(name, lastname)
    
# Facebook
def facebook(name, lastname):
    
    facebook = f"https://fr-fr.facebook.com/public/{name}{lastname}"
    print(f"{Fore.YELLOW}[!] Facebook{Fore.GREEN}")
    
    try:
        page = requests.get(facebook).content.decode('utf-8')
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}HTTP error : {e}{Fore.GREEN}")   
        return
    
    nameAccount = re.findall(r'width="72" height="72" alt="([a-zA-Z0-9_ é , ]+)" />', page)
    full_name = f"{name} {lastname}".lower() 
    count = sum(1 for account in nameAccount if full_name in account.lower())

    if count == 0:
        print(f"{Fore.YELLOW}No results found for '{name} {lastname}'{Fore.GREEN}\n\n")
    else:
        print(f"[+] {Fore.YELLOW}Probable results found : {count}{Fore.GREEN}")
        print(f"[+] {Fore.YELLOW}Link : {facebook}{Fore.GREEN}")
        print("")
  
    
# Copains d'avant
def initdata(name, lastname):
    url = 'https://copainsdavant.linternaute.com/s/?q={}+{}&ty=1&xhr='.format(name, lastname)
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        print(f"{Fore.RED}HTTP error occurred : {http_err}")
    except Exception as err:
        print(f"{Fore.RED}Other error occurred : {err}")
    return None

def showprofile(profile):
    try: print(f"[+] {Fore.YELLOW}Profil name : {Fore.GREEN}{profile.get('ti', 'No Title')}") 
    except Exception: pass
    try: print(f"[+] {Fore.YELLOW}ID : {Fore.GREEN}{profile.get('id', 'No ID')}") 
    except Exception: pass
    try: print(f"[+] {Fore.YELLOW}Picture : {Fore.GREEN}{profile.get('photo', 'No Photo')} {profile.get('id', 'No ID') + 1}") 
    except Exception: pass
    try: print(f"[+] {Fore.YELLOW}Infos : {Fore.GREEN}{profile.get('label', 'No Label')} {profile.get('id', 'No ID') + 2}") 
    except Exception: pass
    print("")

def copains_davant(name, lastname):
    data = initdata(name, lastname)

    if data and 'r' in data:
        print(f"{Fore.YELLOW}[!] Copains d'avant{Fore.GREEN}")
        print(f"{Fore.YELLOW}[?] Source : {Fore.GREEN}https://copainsdavant.linternaute.com/s/?q={name}+{lastname}")

        for profile in data['r']:
            profile_id = profile.get('id')
            showprofile(profile)  


# Wattpad
def wattpad(name,lastname):
    try:
        url = f"https://www.wattpad.com/search/{name}%20{lastname}/people"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Vérifie que la requête a réussi
        source_code = response.text

        if "Hmmm... il n'y a pas de résultats" in source_code:
            return None
        else:
            print(f"[!] {Fore.YELLOW}Wattpad{Fore.GREEN}")
            print(f"[+] {Fore.YELLOW}Profile found : {Fore.GREEN}{url}")
    except Exception as e:
        print(e)
        pass


#Avis de décès
def morts(name, lastname):
    url = f"https://avis-deces.linternaute.com/recherche-avis?q={name} {lastname}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    
    try:
        r = requests.get(url)
        page = r.content
        features = "html.parser"
        soup = BeautifulSoup(page, features)

        names  = soup.find_all('h4')
        ages   = soup.find_all('small')
        villes = soup.find_all('div',{'class':'odResultList__details--death'})
        profile_list = []

        for i in range(len(names)):
            try:
                name = names[i].text.split('(')[0].replace('\r','').replace('\n','').replace('\t','').strip()
                loc  = villes[i].text.split('à')[1].replace('\n','').replace('                     ','').strip()
                age  = ages[i].text.strip()
                dictt = {'Name':name,'Age':str(age),'Loc':loc.replace('- ','')}
                profile_list.append(dictt)
            except IndexError:
                pass

        if len(names) == 0:
            pass
        else:
            print(f"{Fore.YELLOW}[!] Avis de décès{Fore.GREEN}")
            print(f"{Fore.YELLOW}[?] Source : {Fore.GREEN}{url}")

            for i in profile_list[:5]:
                print(f"{Fore.GREEN}[+] {Fore.YELLOW}" + '{} | {}\t| {}'.format(i['Age'],i['Name'],i['Loc']))
            
    except requests.RequestException as e:
        print(f"{Fore.RED}Request error : {e}")


# Pages blanches
def pagesblanches(name, lastname):
    url = f'https://www.118000.fr/search?part=1&who={lastname} {name}'
    r = requests.get(url)
    page = r.content
    soup = BeautifulSoup(page, "html.parser")
    
    # Trouver tous les résultats
    results = soup.find_all("section", class_="card part lnk")
    
    # Vérifier s'il y a des résultats
    if not results:
        return

    print(f"{Fore.YELLOW}[!] Pages blanches{Fore.GREEN}")
    print(f"{Fore.YELLOW}[?] Source : {Fore.GREEN}{url}")
    print("")

    for result in results:
        name_element = result.find("h2", class_="name title inbl")
        target_name = name_element.text.strip() if name_element else "-"
        
        addr_element = result.find("div", class_="h4 address mtreset")
        target_addr = addr_element.text.strip() if addr_element else "-"
        
        phone_element = result.find('a', class_='clickable atel')
        target_phon = phone_element.text.strip() if phone_element else "-"
        
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Name       : {Fore.GREEN}{target_name}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Adress     : {Fore.GREEN}{target_addr}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Phone      : {Fore.GREEN}{target_phon}")
        print("")


# BAC + BREVET
def bac(name, lastname):
    url = f'https://resultats.etudiant.lefigaro.fr/resultats-bac/recherche?name={name} {lastname}&city_label=&city_insee='
    r = requests.get(url)
    page = r.content
    soup = BeautifulSoup(page, "html.parser")
    profiles = soup.find_all('td',{'class':'svelte-11did2l'})   
    listt = [] 
    for i in profiles:
        if len(listt) == 1:
            subject = listt[0]
            link = "https://resultats.etudiant.lefigaro.fr"+subject.split('href="')[1].split('">')[0]
            academie = None
            mention  = None
            ville    = None
            diplome  = None
            r        = requests.get(link)
            page     = r.content
            soup     = BeautifulSoup(page, "html.parser")

            mention  = soup.find('span',{'class':'block text-4xl text-red'}).text.split('"')[1].split('"')[0]
            diplome  = soup.find('p',{'class':'text-grey-600 mb-1'}).text.strip()
            academie = soup.find('div',{'class':'flex flex-col items-center sm:flex-row flex-wrap gap-5'}).text.split(',')[1].strip()
            city     = soup.find('a',{'class':'capitalize underline'}).text.strip()
            
            return {
                'Exists': True,
                'academy': academie,
                'Link': url,
                'mention': mention,
                'city': ville,
                'Diploma': diplome
            }
            
        elif len(listt) == 0:
            profile = str(i).lower()
            if name.lower() in profile and lastname.lower() in profile:
                    listt.append(profile)
    return {'Exists': False}
          
          
def brevet(name, lastname):
    url = f'https://resultats.etudiant.lefigaro.fr/resultats-brevet/recherche?name={lastname} {name}&city_label=&city_insee='
    r = requests.get(url)
    page = r.content
    soup = BeautifulSoup(page, "html.parser")
    profiles = soup.find_all('div',{'class':'bg-white p-2'})    
    for i in profiles:
        profile = str(i).lower()
        if name.lower() in profile and lastname.lower() in profile:
            url = "https://resultats.etudiant.lefigaro.fr"+profile.split('href')[1].split('"')[1]
            r = requests.get(url)
            page = r.content
            features = "html.parser"
            soup = BeautifulSoup(page, features)
            
            profile = soup.find('div',{'class':'box'})
            mention = soup.find('span',{'class':'block text-4xl text-red'})
            diplome = soup.find('p',{'class':'text-grey-600 mb-1'})

            diplome    = str(diplome).split('text-grey-600 mb-1">')[1].split('</p>')[0]
            nom_prenom = str(profile).split('h1>')[1].split('<span')[0]
            ville      = str(profile).split('capitalize">')[1].split('</span>')[0]
            academie   = str(profile).split('(')[1].split(')')[0]
            mention    = str(mention).split('class="block text-4xl text-red">')[1].split('</span>')[0]


            return {
                'Exists': True,
                'Name': nom_prenom,
                'academy': academie,
                'Link': url,
                'mention': mention,
                'city': ville,
                'Diploma': diplome
            }
    return {'Exists': False}  


def bac_brevet(name, lastname):
    bac_result = bac(name, lastname)
    brevet_result = brevet(name, lastname)
    
    if bac_result['Exists']:
        print('DIPLOME BAC')
        print(f'Bac     : {bac_result["Diploma"]}')
        print(f'Academy : {bac_result["academy"]}')
        print(f'Mention : {bac_result["mention"]}')
        print(f'City    : {bac_result["city"]}')
        print(f'Source  : {bac_result["Link"]}')
    
    if brevet_result['Exists']:
        print('BREVET DES COLLEGES')
        print(f'Name     : {brevet_result["Name"]}')
        print(f'Diploma  : {brevet_result["Diploma"]}')
        print(f'Details  : {brevet_result["mention"]}')
        print(f'Academy  : {brevet_result["academy"]}')
        print(f'Location : {brevet_result["city"]}')
        print(f'Source   : {brevet_result["Link"]}')

        


