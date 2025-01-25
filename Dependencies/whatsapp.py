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
        print(f"{Fore.YELLOW}Phone Number        : {Fore.GREEN}{response_json['phone']}")
        print(f"{Fore.YELLOW}Country Code        : {Fore.GREEN}{response_json['countryCode']}")
        print(f"{Fore.YELLOW}User ID             : {Fore.GREEN}{response_json['id']['user']}")
        print(f"{Fore.YELLOW}User Serialized     : {Fore.GREEN}{response_json['id']['_serialized']}")
        print(f"{Fore.YELLOW}Server              : {Fore.GREEN}{response_json['id']['server']}")
        print(f"{Fore.YELLOW}Is Business Account : {Fore.GREEN}{'Yes' if response_json['isBusiness'] else 'No'}")
        print(f"{Fore.YELLOW}Labels              : {Fore.GREEN}{response_json['labels'] if response_json['labels'] else 'No labels'}")
        print(f"{Fore.YELLOW}Is Me               : {Fore.GREEN}{'Yes' if response_json['isMe'] else 'No'}")
        print(f"{Fore.YELLOW}Is User             : {Fore.GREEN}{'Yes' if response_json['isUser'] else 'No'}")
        print(f"{Fore.YELLOW}Is Group            : {Fore.GREEN}{'Yes' if response_json['isGroup'] else 'No'}")
        print(f"{Fore.YELLOW}Is WA Contact       : {Fore.GREEN}{'Yes' if response_json['isWAContact'] else 'No'}")
        print(f"{Fore.YELLOW}Is My Contact       : {Fore.GREEN}{'Yes' if response_json['isMyContact'] else 'No'}")
        print(f"{Fore.YELLOW}Is Blocked          : {Fore.GREEN}{'Yes' if response_json['isBlocked'] else 'No'}")
        print(f"{Fore.YELLOW}About               : {Fore.GREEN}{response_json['about']}")
        print(f"{Fore.YELLOW}Profile Picture     : {Fore.GREEN}{response_json['profilePic']}")
        
    except FileNotFoundError:
        abs_path = os.path.abspath(token_file_path)
        print(f"\n{Fore.RED}[!] File 'Tokens/whatsapp_token_rapidapi.txt' not found.")
        print(f"{Fore.YELLOW}Searched in: {abs_path}{Fore.RED}")
        
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error : {e}{Fore.YELLOW}")

