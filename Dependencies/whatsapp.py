import http.client, os, json
from colorama import Fore, init

init()

conn = http.client.HTTPSConnection("whatsapp-data1.p.rapidapi.com")

token_file_path = 'Tokens/whatsapp_token_rapidapi.txt' 

headers = {
    'x-rapidapi-host': "whatsapp-data1.p.rapidapi.com"
}

def getwhatsappinfos(phone):
    try:
        with open(token_file_path, "r") as file:
            api_token = file.read().strip()  

        headers['x-rapidapi-key'] = api_token  
        conn.request("GET", f"/number/{phone}", headers=headers)

        res = conn.getresponse()
        data = res.read()
        response_json = json.loads(data.decode("utf-8"))
        
        print(f"\n{Fore.YELLOW}[!] Whatsapp infos")
        print(f"{Fore.YELLOW}Phone Number        : {Fore.GREEN}{response_json.get('phone')}")
        print(f"{Fore.YELLOW}Country Code        : {Fore.GREEN}{response_json.get('countryCode')}")

        id_data = response_json.get("id", {})

        print(f"{Fore.YELLOW}User ID             : {Fore.GREEN}{id_data.get('user')}")
        print(f"{Fore.YELLOW}User Serialized     : {Fore.GREEN}{id_data.get('_serialized')}")
        print(f"{Fore.YELLOW}Server              : {Fore.GREEN}{id_data.get('server')}")

        print(f"{Fore.YELLOW}Is Business Account : {Fore.GREEN}{'Yes' if response_json.get('isBusiness') else 'No'}")
        print(f"{Fore.YELLOW}Labels              : {Fore.GREEN}{response_json.get('labels', 'No labels')}")
        print(f"{Fore.YELLOW}Is Me               : {Fore.GREEN}{'Yes' if response_json.get('isMe') else 'No'}")
        print(f"{Fore.YELLOW}Is User             : {Fore.GREEN}{'Yes' if response_json.get('isUser') else 'No'}")
        print(f"{Fore.YELLOW}Is Group            : {Fore.GREEN}{'Yes' if response_json.get('isGroup') else 'No'}")
        print(f"{Fore.YELLOW}Is WA Contact       : {Fore.GREEN}{'Yes' if response_json.get('isWAContact') else 'No'}")
        print(f"{Fore.YELLOW}Is My Contact       : {Fore.GREEN}{'Yes' if response_json.get('isMyContact') else 'No'}")
        print(f"{Fore.YELLOW}Is Blocked          : {Fore.GREEN}{'Yes' if response_json.get('isBlocked') else 'No'}")

        print(f"{Fore.YELLOW}About               : {Fore.GREEN}{response_json.get('about', 'No bio')}")
        print(f"{Fore.YELLOW}Profile Picture     : {Fore.GREEN}{response_json.get('profilePic', 'No picture')}")
        
    except FileNotFoundError:
        abs_path = os.path.abspath(token_file_path)
        print(f"\n{Fore.RED}[!] File 'Tokens/whatsapp_token_rapidapi.txt' not found.")
        print(f"{Fore.YELLOW}Searched in: {abs_path}{Fore.RED}")
        
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error : {e}{Fore.YELLOW}\n")
        print(json.dumps(response_json, indent=2))

