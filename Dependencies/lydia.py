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

    def fetch_all_pots_links():
        url = "https://search.brave.com/search?q=https%3A%2F%2Fpots.lydia.me%2Fcollect%2Fpots%3Fid%3D&source=web"
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            links = soup.find_all("a", href=True)
            pots_links = [link['href'] for link in links if "/collect/" in link['href']]
            print(f"✅ {len(pots_links)} pot links found.")
            return pots_links
        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching Brave Search: {e}")
            return []

    def get_uuid(slug):
        data = {
            "slug": slug,
            "price": "10",
            "customdata[name-key]": "who cares",
            "customdata[amount-key]": "10",
            "customdata[recipient-key]": f"{phone_info}",
            "payment_method": "lydia"
        }

        for attempt in range(2):
            response = requests.post("https://pots.lydia.me/collect/createrequest?",
                                     headers=headers, data=data, allow_redirects=False)
            location = response.headers.get("Location", "")                         
            match = re.search(r"/collect/payment/([a-fA-F0-9]{32})/", location)
            if match:
                uuid = match.group(1)
                print(f"✅ UUID retrieved : {uuid}")
                return uuid
            print(f"❌ No redirection detected (attempt {attempt + 1}/2), retrying...")
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

    pots_links = fetch_all_pots_links()
    if not pots_links:
        print("⛔ No links to test. Aborting.")
        return

    for i, pot_url in enumerate(pots_links[:6], start=1):
        print(f"🔄 Attempt {i}/6")
        if pot_url in dico:
            continue
        dico.append(pot_url)
        print(f"➡️ Testing URL : {pot_url}")
        try:
            pot_response = requests.get(pot_url, headers=headers)
            if "error?code=" not in pot_response.url:
                match = re.search(r"/collect/([^/?]+)", pot_url)
                if match:
                    slug = match.group(1)
                    print(f"🔹 Extracted slug: {slug}")
                    uuid = get_uuid(slug)
                    if uuid:
                        get_first_name(uuid)
                        break
                    else:
                        print("❌ UUID not found.")
            else:
                print("❌ Invalid pot link.")
        except Exception as e:
            print(f"⚠️ Error testing pot URL: {e}")
