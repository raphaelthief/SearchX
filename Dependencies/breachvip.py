import httpx, html, requests, re, json

# colorama
from colorama import init, Fore, Style

init() # Init colorama

cf_clearance_cookies = None
session_cookies = None

def load_breachvip_credentials():
    global session_cookies, cf_clearance_cookies
    
    try:
        file_path = 'Tokens/breachvip.txt'
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
            if not lines:
                return False

            for line in lines:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                key, value = line.split(":", 1)
                key, value = key.strip(), value.strip()

                if key == "cf_clearance":
                    cf_clearance_cookies = value
                elif key == "session":
                    session_cookies = value
       
        
        if not (cf_clearance_cookies and session_cookies):
            return False
        else:
            return True
            
    except FileNotFoundError:
        print(f"{Fore.RED}[!] breachvip.txt not found ...")
        return False


def breachvip_init(target, what):
    try:
        load_or_not = load_breachvip_credentials()
        if load_or_not:

            headers = {
                "Host": "breach.vip",
                "Cookie": f"session={session_cookies}; cf_clearance={cf_clearance_cookies}",
                "Cache-Control": "max-age=0",
                "Sec-Ch-Ua": '"Chromium";v="135", "Not-A.Brand";v="8"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Accept-Language": "fr-FR,fr;q=0.9",
                "Origin": "https://breach.vip",
                "Content-Type": "application/x-www-form-urlencoded",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
                "Referer": "https://breach.vip/",
                "Accept-Encoding": "gzip, deflate, br",
                "Priority": "u=0, i"
            }

            data = {
                "query": target,
                "type": what
            }

            with httpx.Client(http2=True, headers=headers) as client:
                response = client.post("https://breach.vip/", data=data)

            pattern = r'<astro-island[^>]*props="([^"]+)"'
            matches = re.findall(pattern, response.text)

            for i, encoded_props in enumerate(matches, 1):
                try:
                    decoded_props = html.unescape(encoded_props)
                    props_json = json.loads(decoded_props)
                    raw_data = props_json["data"][1]

                    data = {}
                    for key, val in raw_data.items():
                        if isinstance(val, list) and len(val) == 2:
                            if isinstance(val[1], list):
                                data[key] = [v[1] for v in val[1]]
                            else:
                                data[key] = val[1]
                        else:
                            data[key] = val

                    source = data.pop("source", None)
                    if source:
                        print(f"\n{Fore.YELLOW}--- {Fore.CYAN}{source} {Fore.YELLOW}--- Entry #{i} ---")
                    for k, v in data.items():
                        color_val = Fore.GREEN if isinstance(v, (str, int, float)) else Fore.MAGENTA
                        print(f"{Fore.YELLOW}{k} : {color_val}{v}")

                except Exception as e:
                    print(f"{Fore.RED}Error entry #{i}")

        else:
            print(f"{Fore.RED}[x] Breachvip wasn't loaded (credencials setup)")
    except Exception as e:
        print(f"{Fore.RED}[x] Unexpected error with Breachvip")


