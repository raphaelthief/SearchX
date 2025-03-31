import requests
import re
import time
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

init()  # Init colorama for colored text in terminal



# Main
def proceed(phone_info):
    
    slug_ID = ""

    # Fonction pour rechercher et afficher les URLs des cagnottes sur la page
    def find_pots_urls():
        # URL de recherche avec Brave (comme dans votre exemple)
        url = "https://search.brave.com/search?q=https%3A%2F%2Fpots.lydia.me%2Fcollect%2Fpots%3Fid%3D&source=web"
        
        # Envoi de la requête GET pour obtenir la page HTML
        response = requests.get(url)
        
        if response.status_code == 200:
            # Parser la page HTML avec BeautifulSoup
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Trouver tous les liens <a> dans la page
            links = soup.find_all("a", href=True)
            
            # Filtrer pour ne garder que les liens qui contiennent "/collect/"
            pots_links = [link['href'] for link in links if "/collect/" in link['href']]
            
            if pots_links:
                print("🔍 Pot URLs found :")
                # Vérifier chaque URL obtenue
                for pot_url in pots_links:
                    # Tester chaque URL pour vérifier si elle est valide
                    print(f"➡️ Testing URL : {pot_url}")
                    
                    # Envoi de la requête GET pour vérifier l'URL de la cagnotte
                    pot_response = requests.get(pot_url)
                    
                    # Si l'URL contient "error?code=", ce n'est pas une cagnotte valide
                    if "error?code=" in pot_response.url:
                        print(f"❌ Error with URL : {pot_url}")
                    else:
                        print(f"✅ Valid pot found : {pot_url}")
                        
                        match = re.search(r"/collect/([^/?]+)", pot_url)
                        if match:
                            slug = match.group(1)
                            slug_ID = slug
                            print(f"🔹 Extracted slug: {slug}\n")
                        return slug_ID  # Stoppe dès qu'une cagnotte valide est trouvée
            else:
                print("❌ No pots found.")
        else:
            print(f"❌ Error retrieving the page: {response.status_code}")

    slug_ID = find_pots_urls()
    # Headers
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
    }

    # Données à envoyer dans la requête POST
    data = {
        "slug": slug_ID,
        "price": "10",
        "customdata[name-key]": "who cares",
        "customdata[amount-key]": "10",
        "customdata[recipient-key]": f"{phone_info}",
        "payment_method": "lydia"
    }


    # Fonction pour obtenir l'UUID après la requête POST
    def get_uuid():
        max_attempts = 3  # Nombre de tentatives max
        attempt = 0
        
        while attempt < max_attempts:
            response = requests.post("https://pots.lydia.me/collect/createrequest?", 
                                     headers=headers, data=data, allow_redirects=False)
            
            if "Location" in response.headers:
                match = re.search(r"/collect/payment/([a-f0-9]{32})/", response.headers["Location"])
                if match:
                    uuid = match.group(1)
                    print(f"✅ UUID retrieved : {uuid}")
                    return uuid
            print("❌ No redirection detected, retrying...")
            #print(response.headers)
            attempt += 1
            time.sleep(2)  # Attente avant une nouvelle tentative
        
        print("❌ Unable to obtain a UUID after multiple attempts")
        return None

    # Fonction pour obtenir et afficher le prénom
    def get_first_name(uuid):
        url_get = f"https://pots.lydia.me/collect/state?uuid={uuid}"
        
        # Attente avant de faire la requête GET pour s'assurer que le serveur a traité
        time.sleep(2)  # Pause avant de faire la requête GET
        
        response_get = requests.get(url_get, headers=headers)
        
        # Parsing du contenu de la page
        soup = BeautifulSoup(response_get.text, "html.parser")
        
        # Extraire le texte de la balise <p class="radar-description">
        description = soup.find("p", class_="radar-description")
        
        if description:
            text = description.text.strip()
            if "," in text:
                first_word = text.split(",")[0]
                print(f"✅ Fist name found : {Fore.YELLOW}", first_word)
            else:
                print("❌ Not found")
        else:
            print("❌ Not found")
        
    
    uuid = get_uuid()
    if uuid:
        get_first_name(uuid)