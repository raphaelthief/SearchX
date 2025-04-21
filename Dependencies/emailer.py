import requests, re, json
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
from urllib.parse import urlparse, parse_qs, urlencode

# colorama
from colorama import init, Fore, Style

init() # Init colorama

M = Fore.MAGENTA
R = Fore.RED
G = Fore.GREEN
Y = Fore.YELLOW
C = Fore.CYAN

trello_organization = None
trello_API = None
trello_TOKEN = None

def load_trello_credentials():
    global trello_organization, trello_API, trello_TOKEN
    
    try:
        file_path = 'Tokens/trello_api.txt'
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

                if key == "trello_organization":
                    trello_organization = value
                elif key == "trello_API":
                    trello_API = value
                elif key == "trello_TOKEN":
                    trello_TOKEN = value

        if not (trello_organization and trello_API and trello_TOKEN):
            return False
        else:
            return True
            
    except FileNotFoundError:
        print(f"{R}[!] trello_api.txt not found ...")
        return False


############################## EMAIL ##############################

def vivino(email):
    url = "https://www.vivino.com/api/login"

    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "x-requested-with": "XMLHttpRequest",
    }

    data = {
        "email": email,
        "password": "xxxxx"
    }

    response = requests.post(url, json=data, headers=headers)

    if response.status_code == 403:
        error_message = response.json().get("error", "").lower()
        if re.search(r"n'existe pas", error_message, re.IGNORECASE) or re.search(r"not exist", error_message, re.IGNORECASE):    
            print(f"{M}[-] www.vivino.com")
        elif re.search(r"mot de passe est incorrect", error_message, re.IGNORECASE) or re.search(r"Password is incorrect", error_message, re.IGNORECASE):        
            print(f"{G}[+] www.vivino.com")
        elif re.search(r"has been locked", error_message, re.IGNORECASE) or re.search(r"bloqué", error_message, re.IGNORECASE):        
            print(f"{G}[+] www.vivino.com")
            print(f"{C} └─ {G}{Y}account locked")
        else:
            print(f"{R}[x] www.vivino.com")  
    elif response.status_code == 429:
        print(F"{R}[x] www.vivino.com")  
    else:
        print(F"{R}[x] www.vivino.com")  


def academia(email):
    session = requests.Session()

    url = "https://www.academia.edu/v0/has_account?subdomain_param=api"
    headers = {
        "accept": "*/*",
        "content-type": "application/json",
        "origin": "https://www.academia.edu",
        "referer": "https://www.academia.edu/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    }

    initial_url = "https://www.academia.edu/"
    initial_response = session.get(initial_url, headers=headers)

    soup = BeautifulSoup(initial_response.text, 'html.parser')
    csrf_token = soup.find('meta', {'name': 'csrf-token'})['content']

    headers["x-csrf-token"] = csrf_token

    data = {"email": email}
    response = session.post(url, json=data, headers=headers)

    if response.status_code == 200:
        response_json = response.json()
        if response_json.get("has_account", False):
            first_name = response_json.get("first_name", "Inconnu")
            print(f"{G}[+] www.academia.edu")
            print(f"{C} └─ {G}First name : {Y}{first_name}")
        else:
            print(f"{M}[-] www.academia.edu")
    elif response.status_code == 429:
        print(f"{R}[x] www.academia.edu")
    else:
        print(f"{R}[x] www.academia.edu")


def adobe_check(email):
    session = requests.Session()  

    url_get = "https://auth.services.adobe.com/"
    session.get(url_get, headers={
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
    })

    url_post = "https://auth.services.adobe.com/signin/v2/users/accounts"

    headers = {
        "accept": "application/json, text/plain, */*",
        "content-type": "application/json",
        "origin": "https://auth.services.adobe.com",
        "referer": "https://auth.services.adobe.com/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Cookie": "relay=tktmonreuf",
        "x-ims-clientid": "homepage_milo"
    }

    data = {"username": email, "usernameType": "EMAIL"}
    response = session.post(url_post, json=data, headers=headers)

    try:
        response_json = response.json()
        
        if isinstance(response_json, list) and len(response_json) > 0:
            account_info = response_json[0]  

            if "authenticationMethods" in account_info:
                print(f"{G}[+] www.adobe.com")

                auth_methods = [method["id"] for method in account_info["authenticationMethods"]]
                print(f"{C} ├─ {G}Target auth methods   : {Y}{', '.join(auth_methods)}")

                if account_info.get("hasT2ELinked", False):
                    print(f"{C} ├─ {G}2MFA                  : {Y}activated")
                    
                if account_info["status"]["code"] == "passwordResetRequired":
                    print(f"{C} ├─ {G}Reset password        : {Y}true")
            
            url2 = "https://auth.services.adobe.com/signin/v2/authenticationstate?purpose=multiFactorAuthentication"
            headers2 = {
                "Host": "auth.services.adobe.com",
                "Cookie": "relay=tktmonreuf",
                "X-Ims-Clientid": "homepage_milo",
                "Sec-Ch-Ua-Platform": "\"Windows\"",
                "Accept-Language": "fr-FR,fr;q=0.9",
                "Sec-Ch-Ua": "\"Not:A-Brand\";v=\"24\", \"Chromium\";v=\"134\"",
                "Sec-Ch-Ua-Mobile": "?0",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
                "Accept": "application/json, text/plain, */*",
                "Content-Type": "application/json",
                "Origin": "https://auth.services.adobe.com",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty",
                "Referer": "https://auth.services.adobe.com/en_US/index.html",
                "Accept-Encoding": "gzip, deflate, br",
                "Priority": "u=1, i"
            }

            payload = {
                "extraPbaChecks": False,
                "pbaPolicy": None,
                "username": email,
                "usernameType": "EMAIL",
                "accountType": "individual"
            }

            response2 = requests.post(url2, headers=headers2, json=payload)
            passkey = response2.headers.get("X-Ims-Authentication-State-Encrypted")

            url3 = "https://auth.services.adobe.com/signin/v3/challenges?purpose=multiFactorAuthentication"
            headers3 = {
                "Host": "auth.services.adobe.com",
                "Cookie": "relay=tktmonreuf; gpv=Account:IMS:GetStarted:OnLoad",
                "X-Ims-Clientid": "homepage_milo",
                "Sec-Ch-Ua-Platform": "\"Windows\"",
                "Accept-Language": "fr-FR,fr;q=0.9",
                "Sec-Ch-Ua": "\"Not:A-Brand\";v=\"24\", \"Chromium\";v=\"134\"",
                "Sec-Ch-Ua-Mobile": "?0",
                "X-Debug-Id": "tktmonreuf",
                "X-Ims-Authentication-State-Encrypted": passkey, 
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
                "Accept": "application/json, text/plain, */*",
                "Content-Type": "application/json",
                "Origin": "https://auth.services.adobe.com",
                "Accept": "application/json, text/plain, */*",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty",
                "Referer": "https://auth.services.adobe.com/en_US/index.html",
                "Accept-Encoding": "gzip, deflate, br",
                "Priority": "u=1, i"
            }

            response3 = requests.get(url3, headers=headers3)
            mfa_infos = response3.json()

            available_factors = mfa_infos.get("availableFactors")
            favorite_factor = mfa_infos.get("favoriteFactor")
            security_phone = mfa_infos.get("securityPhoneNumber")
            secondary_email = mfa_infos.get("secondaryEmail")


            if any([available_factors, favorite_factor, security_phone, secondary_email]):
                factors = []
                if available_factors:
                    factors.append(f"Available MFA factors : {Y}{available_factors}")
                if favorite_factor:
                    factors.append(f"Favorite factor       : {Y}{favorite_factor}")
                if security_phone:
                    factors.append(f"Security phone        : {Y}{security_phone}")
                if secondary_email:
                    factors.append(f"Secondary email       : {Y}{secondary_email}")

                for i, factor in enumerate(factors):
                    if i == len(factors) - 1:  
                        print(f"{C} └─ {G}{factor}")   
                    else:  
                        print(f"{C} ├─ {G}{factor}")  
            
            else:
                print(f"{M}[-] www.adobe.com")  
        else:
            print(f"{M}[-] www.adobe.com")  
    except Exception as e:
        print(f"{R}[x] www.adobe.com")


def trello(email):
    try:
        load_or_not = load_trello_credentials()
        if load_or_not:
            
            url = f"https://api.trello.com/1/search/members?idOrganization={trello_organization}&query={email}&key={trello_API}&token={trello_TOKEN}"
            request_trello = requests.get(url)
            response = request_trello.json()

            if isinstance(response, list) and response:
                member = response[0]

                if member.get("memberType") == "ghost":
                    print(f"{M}[-] trello.com")
                else:
                    print(f"{G}[+] trello.com")
                    print(f"{C} ├─ {G}ID            : {Y}{member.get('id')}")
                    print(f"{C} ├─ {G}Full name     : {Y}{member.get('fullName')}")
                    print(f"{C} ├─ {G}Username      : {Y}{member.get('username')}")
                    print(f"{C} ├─ {G}Confirmed     : {Y}{member.get('confirmed')}")
                    print(f"{C} ├─ {G}Active        : {Y}{member.get('active')}")
                    print(f"{C} ├─ {G}Last activity : {Y}{member.get('dateLastActive')}")
                    print(f"{C} ├─ {G}Email         : {Y}{member.get('email') or 'Non disponible'}")
                    print(f"{C} └─ {G}Member type   : {Y}{member.get('memberType')}")

            else:
                print(f"{M}[-] trello.com")
        else:
            print(f"{R}[x] trello.com (setup api key)")
    except Exception as e:
        print(f"{R}[x] trello.com")


def spotify(email):
    url = f"https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={email}"

    response = requests.get(url)
    if response.status_code == 200:
        try:
            data = response.json()  
            if data.get("status") == 20 and "email" in data.get("errors", {}):
                print(f"{G}[+] spotify.com")  
            elif data.get("status") == 429:  
                print(f"{R}[x] spotify.com")  
            else:
                print(f"{M}[-] spotify.com")  
        except ValueError:
            print(f"{R}[x] spotify.com")  
    else:
        print(f"{R}[x] spotify.com") 


def deliveroo(email):
    url = "https://api.uk.deliveroo.com/consumer/accounts/check-email"
    data = {
        "email_address": email, 
        "redirect_path": "/",
        "page_in_progress": "login"
    }
    response = requests.post(url, data=json.dumps(data))
    if response.status_code == 200:
        try:
            data = response.json() 

            if data.get("registered") == True:
                print(f"{G}[+] deliveroo.com")  

                identity_providers = data.get("identity_providers", [])
                if identity_providers:
                    for i, provider in enumerate(identity_providers):
                        if i == len(identity_providers) - 1:
                            print(f"{C} └─ {G}ID provider : {Y}{provider}")
                        else:
                            print(f"{C} ├─ {G}ID provider : {Y}{provider}")
        except ValueError:
            print(f"{R}[x] deliveroo.com") 
    elif response.status_code == 404:
        try:
            data = response.json() 
            if data.get("registered") == False:
                print(f"{M}[-] deliveroo.com")
        except ValueError:
            print(f"{R}[x] deliveroo.com")         
    else:    
        print(f"{R}[x] deliveroo.com") 


def apple(email):
    url = "https://idmsa.apple.com/appleauth/auth/federate"
    headers = {
        "Host": "idmsa.apple.com",
        "X-Apple-Domain-Id": "44",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "X-Apple-Oauth-State": "auth-znf6cgcu-bn5u-p27k-tqof-m11f7fy9",
        "Sec-Ch-Ua": '"Chromium";v="135", "Not-A.Brand";v="8"',
        "X-Apple-Locale": "fr_FR",
        "Sec-Ch-Ua-Mobile": "?0",
        "X-Apple-Frame-Id": "auth-znf6cgcu-bn5u-p27k-tqof-m11f7fy9",
        "X-Apple-Oauth-Response-Mode": "web_message",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "X-Apple-Oauth-Redirect-Uri": "https://secure9.store.apple.com",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "X-Apple-Oauth-Response-Type": "code",
        "X-Apple-Oauth-Client-Type": "firstPartyAuth",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Origin": "https://idmsa.apple.com",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://idmsa.apple.com/",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=0, i",
        "Connection": "keep-alive"
    }
    payload = {
        "accountName": email,
        "rememberMe": False
    }

    # Envoi de la requête
    response = requests.post(url, headers=headers, data=json.dumps(payload))

    # Analyse de la réponse
    if response.status_code == 200:
        try:
            data = response.json()
            if data.get("hasSWP") is True:
                print(f"{G}[+] apple.com")
            else:
                print(f"{M}[-] apple.com")
        except ValueError:
            print(f"{R}[x] apple.com (invalid JSON)")
    else:
        print(f"{R}[x] apple.com (status {response.status_code})")


def paypal(email):
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            page = browser.new_page()

            page.goto("https://www.paypal.com/authflow/password-recovery/?country.x=US&locale.x=fr_XC&redirectUri=%252Fsignin")
            page.wait_for_load_state('domcontentloaded')

            email_input_locator = page.locator("#pwrStartPageEmail")  
            url_before = page.url

            if email_input_locator.is_visible():
                email_input_locator.fill(email)  
                
                submit_button = page.locator("#pwrStartPageSubmit") 
                submit_button.click()  
                
                page.wait_for_load_state('networkidle')  

            current_url = page.url  
            
            if current_url != url_before:
                parsed_url = urlparse(current_url)  
                #query_params = parse_qs(parsed_url.query)  
                page_content = page.content()  
                
                soup = BeautifulSoup(page_content, 'html.parser')
                option_labels = soup.find_all('p', class_='challengeOptionLabel')

                print(f"{G}[+] paypal.com")
                for label in option_labels:
                    option_value = label.find('span', {'data-nemo': 'optionLabel'}).get_text(strip=True)
                    print(f"{C} ├─ {G}{option_value}")
                    
            else:
                print(f"{M}[-] paypal.com")
                
            browser.close()

    except Exception as e:
        print(f"{R}[x] paypal.com")
        print(f"{C} ├─ {R}Try : https://www.paypal.com/authflow/password-recovery/?country.x=US&locale.x=fr_XC&redirectUri=%252Fsignin")


def ebay(email):
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            context = browser.new_context(
                user_agent="Mozilla/6.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            )
            page = context.new_page()

            page.goto("https://signin.ebay.com/ws/eBayISAPI.dll?SignIn&sgfl=gh&ru=https%3A%2F%2Fwww.ebay.com%2F")
            page.wait_for_load_state('domcontentloaded')
            email_input = page.locator("#userid")
            if email_input.is_visible():


                email_input.fill(email)
                continue_button = page.locator("#signin-continue-btn")
                continue_button.click()
                page.wait_for_load_state('networkidle')
                reset_button = page.locator("text=Reset your password")
                if reset_button.is_visible():
                    reset_button.click()
                    page.wait_for_load_state('networkidle')

                    html = page.content()
                    soup = BeautifulSoup(html, 'html.parser')

                    print(f"{G}[+] ebay.com")
                    b_tag = soup.select_one('div.hub-option-info p#text-desc span b')
                    if b_tag:
                        phone_masked = b_tag.get_text(strip=True)
                        print(f"{C} ├─ {G}{phone_masked}")

                else:                
                    html = page.content()
                    soup = BeautifulSoup(html, 'html.parser')
                    target_text = "We couldn't find this eBay account."
                    found_text = soup.find_all(string=target_text)

                    if found_text:
                        print(f"{M}[-] ebay.com")
                    else:
                        print(f"{R}[x] ebay.com (capcha)")
                        print(f"{C} ├─ {R}Try : https://signin.ebay.com/ws/eBayISAPI.dll?SignIn&sgfl=gh&ru=https%3A%2F%2Fwww.ebay.com%2F")
                        print(f"{C} ├─ {R}--> Password reset for any phone numbers")

            else:
                print(f"{R}[x] ebay.com (capcha)")
                print(f"{C} ├─ {R}Try : https://signin.ebay.com/ws/eBayISAPI.dll?SignIn&sgfl=gh&ru=https%3A%2F%2Fwww.ebay.com%2F")
                print(f"{C} ├─ {R}--> Password reset for any phone numbers")

        browser.close()
    except Exception as e:
        pass


def gravatar(email):
    url = f"https://public-api.wordpress.com/rest/v1.1/auth/get-gravatar-info?http_envelope=1&email={email}"
    response = requests.get(url)
    data = response.json()
    code = data.get("code")
    body = data.get("body", {})

    if response.status_code == 200:
        if code == 200 and "is_secondary" in body:
            print(f"{G}[+] gravatar.com")
        elif code == 404 and body.get("error") == "not_found":
            print(f"{M}[-] gravatar.com")
        else:
            print(f"{R}[x] gravatar.com")
    else:
        print(f"{R}[x] gravatar.com")


def strava(email):
    params = {"email": email}
    response = requests.get("https://www.strava.com/frontend/athletes/email_unique", params=params)
    if response == "true":
        print(f"{G}[+] strava.com")
    elif response == "false":
        print(f"{M}[-] strava.com")
    else:
        print(f"{R}[x] strava.com")

    
def twitter1(email):
    response = requests.get(f"https://api.twitter.com/i/users/email_available.json?email={email}")
    data = response.json()

    if data.get("taken") is True:
        print(f"{G}[+] twitter/x.com")
    elif data.get("taken") is False:
        print(f"{M}[-] twitter/x.com")
    else:
        print(f"{R}[x] twitter/x.com")


def instagram(email):
    response = requests.get("https://www.instagram.com/accounts/emailsignup/")
    csrf_token = response.cookies.get('csrftoken')
    if not csrf_token:
        print(f"{R}[x] instagram.com")
    else:
        data = {
            'email': email,
            'first_name': '',
            'username': '',
            'opt_into_one_tap': False
        }

        headers = {
            'x-csrftoken': csrf_token
        }

        response2 = requests.post("https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/", headers=headers, data=data)
        code = response2.json().get('errors', {}).get('email', [{}])[0].get('code')

        if code == 'email_is_taken':
            print(f"{G}[+] instagram.com")
        else:
            print(f"{M}[-] instagram.com")


def chess(email):
    response = requests.post(f"https://www.chess.com/callback/email/available?email={email}")
    data = response.json()
    
    if data.get("isEmailAvailable") is True:
        print(f"{M}[-] chess.com")
    elif data.get("isEmailAvailable") is False:
        print(f"{G}[+] chess.com")
    else:
        print(f"{R}[x] chess.com")
        

def lastpass(email):
    data = {
        'check': "avail",
        'skipcontent': 1,
        'mistype': 1,
        'username': email
    }
    headers = {
        "sec-ch-ua-platform": "Windows",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
    }

    response = requests.get(f"https://lastpass.com/create_account.php?check=avail&skipcontent=1&mistype=1&username={email}", headers=headers, data=data)

    if response.text == "ok":
        print(f"{M}[-] lastpass.com")
    elif response.text == "no":
        print(f"{G}[+] lastpass.com")
    else:
        print(f"{R}[x] lastpass.com")


def deezer(email):
    s = requests.Session()
    r = s.post("https://www.deezer.com/ajax/gw-light.php?method=deezer.getUserData&input=3&api_version=1.0&api_token=&cid=")
    token = r.json()['results']['checkForm']
    
    params = {
        'method': 'deezer.emailCheck',
        'input': 3,
        'api_version': 1.0,
        'api_token': token,
    }

    api = s.post(f"https://www.deezer.com/ajax/gw-light.php", params=params, data='{"EMAIL":"'+ email +'"}')

    if api.json()['results']['availability'] == True:
        print(f"{M}[-] deezer.com")
    elif api.json()['results']['availability'] == False:
        print(f"{G}[+] deezer.com")
    else:
        print(f"{R}[x] deezer.com")
    s.close()


def duolingo(email):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(f"https://www.duolingo.com/2017-06-30/users?email={email}", headers=headers)

        if response.status_code == 200:
            if response.text.strip():  
                try:
                    data = response.json()
                    if "users" in data and len(data["users"]) > 0:
                        user = data["users"][0]
                        print(f"{G}[+] duolingo.com")
                        if user.get("username"):
                            print(f"{C} ├─ {G}Username : {user['username']}")
                        if user.get("name"):
                            print(f"{C} ├─ {G}Name : {user['name']}")
                        if "hasRecentActivity15" in user:
                            print(f"{C} ├─ {G}Recent activity : {user['hasRecentActivity15']}")
                            
                            
                    else:
                        print(f"{M}[-] duolingo.com")
                except ValueError as e:
                    print(f"{R}[x] duolingo.com")
            else:
                print(f"{R}[x] duolingo.com")
        else:
            print(f"{R}[x] duolingo.com")
    except requests.RequestException as e:
        print(f"{R}[x] duolingo.com")


def mym1(email):
    
    headers = {
        "Host": "mym.fans",
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Accept": "application/json, text/plain, */*",
        "Sec-Ch-Ua": "\"Chromium\";v=\"135\", \"Not-A.Brand\";v=\"8\"",
        "Content-Type": "application/json;charset=UTF-8",
        "Sec-Ch-Ua-Mobile": "?0",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Origin": "https://mym.fans",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://mym.fans/app/register/email",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=1, i"
    }

    payload = {
        "email": email
    }

    response = requests.post("https://mym.fans/app/ajax/email-uniqueness", headers=headers, data=json.dumps(payload))

    try:
        data = response.json()
        if data.get("exist"):
            print(f"{G}[+] mym.fans")
        else:
            print(f"{M}[-] mym.fans")
    except Exception as e:
        print(f"{R}[x] mym.fans")


def pornhub(email):
    session = requests.Session()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
    }
    response = session.get("https://fr.pornhub.com/", headers=headers)
    soup = BeautifulSoup(response.text, "html.parser")
    token_input = soup.find("input", {"name": "token", "type": "hidden"})

    if not token_input or not token_input.get("value"):
        print(f"{R}[x] pornhub.com")
        return

    token = token_input["value"]
    post_url = f"https://fr.pornhub.com/user/create_account_check?token={token}"

    post_headers = {
        "User-Agent": headers["User-Agent"],
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": "https://fr.pornhub.com",
        "Referer": "https://fr.pornhub.com/",
        "Accept-Language": "fr-FR,fr;q=0.9"
    }
    post_data = {
        "check_what": "email",
        "email": email
    }
    post_response = session.post(post_url, headers=post_headers, data=post_data)

    try:
        result = post_response.json()
        if result.get("email") == "create_account_passed":
            print(f"{M}[-] pornhub.com")
        elif result.get("email") == "create_account_failed":
            print(f"{G}[+] pornhub.com")
        else:
            print(f"{R}[x] pornhub.com")

    except Exception as e:
        print(f"{R}[x] pornhub.com")


def xnxx(email):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
        }
        response = requests.get(f"https://www.xnxx.com/account/checkemail?email={email}", headers=headers)
        data = response.json()

        if data.get("result"):
            print(f"{M}[-] xnxx.com")
        else:
            print(f"{G}[+] xnxx.com")
    except Exception as e:
        print(f"{R}[x] xnxx.com")


def xvideos(email):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
        }
        response = requests.get(f"https://www.xnxx.com/account/checkemail?email={email}", headers=headers)
        data = response.json()

        if data.get("result"):
            print(f"{M}[-] xvideos.com")
        else:
            print(f"{G}[+] xvideos.com")
    except Exception as e:
        print(f"{R}[x] xvideos.com")


def youporn(email):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
        }
        payload = {
             "email": email
        }        
        response = requests.post("https://www.youporn.com/register/verify_email", headers=headers, data=payload)
        data = response.json()

        if data.get("success"):
            print(f"{M}[-] youporn.com")
        else:
            print(f"{G}[+] youporn.com")
    except Exception as e:
        print(f"{R}[x] youporn.com")


def tukif(email):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Origin": "https://tukif.porn",
            "Referer": "https://tukif.porn/",
            "X-Requested-With": "XMLHttpRequest",
        }

        data = {
            "signup_username": "username_fucked_dsfkuhiugshifguh",
            "signup_password": "azerty12345",
            "signup_conf_password": "azerty12345",
            "signup_email": email
        }

        response = requests.post("https://tukif.porn/user/signup/", headers=headers, data=urlencode(data))
        result = response.json()
        message = result.get("message", "")
        if "addresse email est déjà utilisée" in message:
            print(f"{G}[+] tukif.porn")
        else:
            print(f"{M}[-] tukif.porn")
    except Exception as e:
        print(f"{R}[x] tukif.porn")



def redtube1(email):
    session = requests.Session()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Accept": "*/*",
        "Origin": "https://fr.redtube.com",
        "Referer": "https://fr.redtube.com/",
        "X-Requested-With": "XMLHttpRequest"
    }

    # 1. Récupération de la page pour récupérer le token
    response = session.get("https://fr.redtube.com/", headers=headers)
    soup = BeautifulSoup(response.text, "html.parser")
    token_tag = soup.find("a", href=True, title="View Mobile Version")

    if not token_tag or "token=" not in token_tag["href"]:
        print(f"{R}[x] redtube.com")
        return

    token = token_tag["href"].split("token=")[1]

    # 2. Construction du corps multipart manuellement
    boundary = "----WebKitFormBoundary96qCHgqLGI9yv3yj"
    post_url = f"https://fr.redtube.com/user/create_account_check?token={token}"

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="email"\r\n\r\n'
        f"{email}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="token"\r\n\r\n'
        f"{token}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="redirect"\r\n\r\n'
        f"\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="check_what"\r\n\r\n'
        f"email\r\n"
        f"--{boundary}--\r\n"
    )

    post_headers = {
        **headers,
        "Content-Type": f"multipart/form-data; boundary={boundary}"
    }

    response = session.post(post_url, headers=post_headers, data=body)

    try:
        result = response.json()
        if result.get("email") == "create_account_passed":
            print(f"{M}[-] redtube.com")
        elif result.get("email") == "create_account_failed":
            print(f"{G}[+] redtube.com")
        else:
            print(f"{R}[x] redtube.com")
    except Exception as e:
        print(f"{R}[x] redtube.com")


def lespompeurs(email):
    headers = {
        "Host": "www.lespompeurs.com",
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Sec-Ch-Ua": "\"Chromium\";v=\"135\", \"Not-A.Brand\";v=\"8\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": "https://www.lespompeurs.com",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://www.lespompeurs.com/inscription",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=1, i"
    }
    data = {
        "action": "checkEmail",
        "email": email
    }
    try:
        response = requests.post("https://www.lespompeurs.com/actions.php", headers=headers, data=data)
        result = response.json()

        if "error" in result.get("results", {}):
            print(f"{G}[+] lespompeurs.com")
        elif result.get("results", {}).get("complete") == "1":
            print(f"{M}[-] lespompeurs.com")
        else:
            print(f"{R}[x] lespompeurs.com")
    except Exception as e:
        print(f"{R}[x] lespompeurs.com")


def candaulib(email):
    headers = {
        "Host": "www.candaulib.com",
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Sec-Ch-Ua": "\"Chromium\";v=\"135\", \"Not-A.Brand\";v=\"8\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": "https://www.candaulib.com",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://www.candaulib.com/inscription-candaulib",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=1, i"
    }
    data = {
        "action": "inscription_chk_contact",
        "contact": email
    }
    try:
        response = requests.post("https://www.candaulib.com/mobile/action2_v5.php", headers=headers, data=data)
        text = response.text.strip()

        if text == "email_used":
            print(f"{G}[+] candaulib.com")
        elif text == "":
            print(f"{M}[-] candaulib.com")
        else:
            print(f"{R}[x] candaulib.com")
    except Exception as e:
        print(f"{R}[x] candaulib.com")


def lovetrans1(email):
    headers = {
        "Host": "www.lovetrans.com",
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Sec-Ch-Ua": "\"Chromium\";v=\"135\", \"Not-A.Brand\";v=\"8\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": "https://www.lovetrans.com/",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=1, i"
    }
    data = {
        "action": "inscription_chk_contact",
        "contact": email
    }
    try:
        response = requests.post("https://www.lovetrans.com/action_index.php", headers=headers, data=data)
        text = response.text.strip()

        if text == "email_invalide":
            print(f"{G}[+] lovetrans.com")
        elif text == "":
            print(f"{M}[-] lovetrans.com")
        else:
            print(f"{R}[x] lovetrans.com")
    except Exception as e:
        print(f"{R}[x] lovetrans.com")


def sexylib1(email):
    headers = {
        "Host": "www.sexylib.com",
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Sec-Ch-Ua": "\"Chromium\";v=\"135\", \"Not-A.Brand\";v=\"8\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": "https://www.sexylib.com/",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=1, i"
    }
    data = {
        "action": "inscription_chk_contact",
        "contact": email
    }
    try:
        response = requests.post("https://www.sexylib.com/mobile/action2_v5.php", headers=headers, data=data)
        text = response.text.strip()

        if text == "email_used":
            print(f"{G}[+] sexylib.com")
        elif text == "":
            print(f"{M}[-] sexylib.com")
        else:
            print(f"{R}[x] sexylib.com")
    except Exception as e:
        print(f"{R}[x] sexylib.com")
        


def gaym(email):
    headers = {
        "Host": "www.gaym.com",
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Sec-Ch-Ua": "\"Chromium\";v=\"135\", \"Not-A.Brand\";v=\"8\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": "https://www.gaym.com/",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=1, i"
    }
    data = {
        "action": "inscription_chk_contact",
        "contact": email
    }
    try:
        response = requests.post("https://www.gaym.com/action_index.php", headers=headers, data=data)
        text = response.text.strip()

        if text == "email_invalide":
            print(f"{G}[+] gaym.com")
        elif text == "":
            print(f"{M}[-] gaym.com")
        else:
            print(f"{R}[x] gaym.com")
    except Exception as e:
        print(f"{R}[x] gaym.com")


def lesrebeux(email):
    headers = {
        "Host": "www.lesrebeus.com",
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Sec-Ch-Ua": "\"Chromium\";v=\"135\", \"Not-A.Brand\";v=\"8\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": "https://www.lesrebeus.com/",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=1, i"
    }
    data = {
        "action": "inscription_chk_contact",
        "contact": email
    }
    try:
        response = requests.post("https://www.lesrebeus.com/action_index.php", headers=headers, data=data)
        text = response.text.strip()

        if text == "email_invalide":
            print(f"{G}[+] lesrebeus.com")
        elif text == "":
            print(f"{M}[-] lesrebeus.com")
        else:
            print(f"{R}[x] lesrebeus.com")
    except Exception as e:
        print(f"{R}[x] lesrebeus.com")


def linktree(email):
    session = requests.Session()
    session.get("https://auth.linktr.ee")
    verify_url = "https://linktr.ee/validate/login/email"

    payload = {"email": email}
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Origin": "https://auth.linktr.ee",
        "Referer": "https://auth.linktr.ee/",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    }
    response = session.post(verify_url, json=payload, headers=headers)
    try:
        data = response.json()
        if "isEmailAvailable" in data:
            if data["isEmailAvailable"]:
                print(f"{M}[-] linktr.ee")
            else:
                print(f"{G}[+] linktr.ee")
        else:
            print(f"{R}[x] linktr.ee")
    except Exception as e:
        print(f"{R}[x] linktr.ee")


def nouslibertin(email):
    headers = {
        "Host": "www.placelibertine.com",
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Sec-Ch-Ua": "\"Chromium\";v=\"135\", \"Not-A.Brand\";v=\"8\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": "https://www.placelibertine.com",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://www.placelibertine.com/",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }
    data = {
        "Inscription[email]": email
    }
    
    response = requests.post("https://www.placelibertine.com/fr/inscription-1", headers=headers, data=data)
    if response.status_code == 200:
        try:
            result = response.json()
            if "email" in result.get("error", {}):
                print(f"{G}[+] placelibertine.com")
            else:
                print(f"{M}[-] placelibertine.com")
        except Exception as e:
            print(f"{R}[x] placelibertine.com")
    else:
        print(f"{R}[x] placelibertine.com")



############################## PHONE ##############################

def apple(phone):
    if phone[3] == '0':
        phone_format = phone[:3] + phone[4:]
    else:
        phone_format = phone

    url = "https://idmsa.apple.com/appleauth/auth/federate"
    headers = {
        "Host": "idmsa.apple.com",
        "X-Apple-Domain-Id": "44",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "X-Apple-Oauth-State": "auth-znf6cgcu-bn5u-p27k-tqof-m11f7fy9",
        "Sec-Ch-Ua": '"Chromium";v="135", "Not-A.Brand";v="8"',
        "X-Apple-Locale": "fr_FR",
        "Sec-Ch-Ua-Mobile": "?0",
        "X-Apple-Frame-Id": "auth-znf6cgcu-bn5u-p27k-tqof-m11f7fy9",
        "X-Apple-Oauth-Response-Mode": "web_message",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "X-Apple-Oauth-Redirect-Uri": "https://secure9.store.apple.com",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "X-Apple-Oauth-Response-Type": "code",
        "X-Apple-Oauth-Client-Type": "firstPartyAuth",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Origin": "https://idmsa.apple.com",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://idmsa.apple.com/",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=0, i",
        "Connection": "keep-alive"
    }
    payload = {
        "accountName": phone_format,
        "rememberMe": False
    }

    # Envoi de la requête
    response = requests.post(url, headers=headers, data=json.dumps(payload))

    # Analyse de la réponse
    if response.status_code == 200:
        try:
            data = response.json()
            if data.get("hasSWP") is True:
                print(f"{G}[+] apple.com")
            else:
                print(f"{M}[-] apple.com")
        except ValueError:
            print("[x] apple.com (invalid JSON)")
    else:
        print(f"{R}[x] apple.com (status {response.status_code})")


def pagesjaunes(phone):
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False) 
            page = browser.new_page()

            url = f"https://www.pagesjaunes.fr/annuaireinverse/recherche?quoiqui={phone}&univers=annuaireinverse&idOu="
            page.goto(url)
            page.wait_for_load_state('domcontentloaded')

            print(page.content())

            try:
                no_result = page.query_selector("h1.wording-no-responses")
                if no_result:
                    print(f"{M}[-] pagesjaunes.fr")
                else:
                    print(f"{G}[+] pagesjaunes.fr")
                    print(f"{C} └─ {G}Visit : https://www.pagesjaunes.fr/annuaireinverse/recherche?quoiqui={phone}&univers=annuaireinverse&idOu=")
            except:
                print(f"{R}[x] pagesjaunes.fr")
                print(f"{C} ├─ {R}Try : https://www.pagesjaunes.fr/annuaireinverse/recherche?quoiqui={phone}&univers=annuaireinverse&idOu=")
            browser.close()

    except Exception as e:
        print(f"{R}[x] pagesjaunes.fr")
        print(f"{C} ├─ {R}Try : https://www.pagesjaunes.fr/annuaireinverse/recherche?quoiqui={phone}&univers=annuaireinverse&idOu=")

    
    
    
    
    
    

############################## USERNAME ##############################
def gravatar1(username):
    url = f"https://public-api.wordpress.com/rest/v1.1/users/{username}/auth-options?http_envelope=1"
    response = requests.get(url)
    data = response.json()
    code = data.get("code")
    body = data.get("body", {})

    if response.status_code == 200:
        if code == 200:
            print(f"{G}[+] gravatar.com")
        elif code == 404 and body.get("error") == "unknown_user":
            print(f"{M}[-] gravatar.com")
        else:
            print(f"{R}[x] gravatar.com")
    else:
        print(f"{R}[x] gravatar.com")

def twitter(username):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
    }

    session = requests.Session()
    response = session.get("https://twitter.com/account/begin_password_reset", headers=headers)

    soup = BeautifulSoup(response.text, "html.parser")
    token_input = soup.find("input", {"name": "authenticity_token"})
    authenticity_token = token_input["value"] if token_input else None

    post_data = {
        "authenticity_token": authenticity_token,
        "account_identifier": username
    }

    post_headers = headers.copy()
    post_headers["Content-Type"] = "application/x-www-form-urlencoded"
    post_headers["Origin"] = "https://twitter.com"
    post_headers["Referer"] = "https://twitter.com/account/begin_password_reset"

    post_response = session.post("https://twitter.com/account/begin_password_reset", data=post_data, headers=post_headers)

    soup_final = BeautifulSoup(post_response.text, "html.parser")

    error_section = soup_final.find("div", class_="PageHeader is-errored")

    email_mask = soup_final.find("strong", attrs={"dir": "ltr"})
    
    
    labels = soup_final.find_all("label")
    last_digits = None
    for label in labels:
        label_text = label.get_text(strip=True)
        if "SMS" in label_text:
            strong_tag = label.find("strong", dir="ltr")
            if strong_tag:
                last_digits = strong_tag.text.strip()
            break  # Stop after first match
    

    error_header = soup_final.find("div", class_="PageHeader is-errored", string=lambda text: text and "n'avons pas pu trouver votre compte" in text)
    error_header_user = soup_final.find('div', class_='PageHeader Edge', string="Vérifiez vos informations personnelles")



    if 'href="https://twitter.com/account/send_password_reset"' in post_response.text:

        twitter_sess = session.cookies.get("_twitter_sess")

        final_headers = headers.copy()
        final_headers["Referer"] = "https://twitter.com/account/begin_password_reset"

        final_response = session.get("https://twitter.com/account/send_password_reset", headers=final_headers)
        soup3 = BeautifulSoup(final_response.text, "html.parser")


        print(f"{G}[+] twitter/x.com")
        email_mask = soup3.find("strong", attrs={"dir": "ltr"})
        if email_mask:
            print(f"{C} ├─ {G}{email_mask.text}")

        if last_digits:
            print(f"{C} ├─ {G}Phone ends with : {last_digits}")



    elif 'href="https://twitter.com/account/password_reset_help?c=5"' in post_response.text:
        print(f"{R}[x] twitter/x.com")
        
    elif error_section and "Veuillez réessayer plus tard" in error_section.text:
        print(f"{R}[x] twitter/x.com")

    elif error_header:
        print(f"{M}[-] twitter/x.com")

    elif error_header_user:
        print(f"{G}[+] twitter/x.com")

    elif 'href="https://twitter.com/account/verify_user_info"' in post_response.text:
        print(f"{G}[+] twitter/x.com")

    elif 'href="https://twitter.com/account/send_password_reset"' in post_response.text:
        print(f"{G}[+] twitter/x.com")

    else:
        found = False
        
        if email_mask:
            found = True
            print(f"{G}[+] twitter/x.com")
            print(f"{C} ├─ {G}{email_mask.text}")
        
        if last_digits:
            if found == False:
                print(f"{G}[+] twitter/x.com")
                
            print(f"{C} ├─ {G}Phone ends with : {last_digits}")

        if found == False:
            print(f"{R}[x] twitter/x.com (capcha)")
            print(f"{C} ├─ {R}Try : https://twitter.com/account/begin_password_reset")


def instagram1(username):
    response = requests.get("https://www.instagram.com/accounts/emailsignup/")
    csrf_token = response.cookies.get('csrftoken')
    if not csrf_token:
        print(f"{R}[x] instagram.com")
    else:
        data = {
            'email': 'thisisafuckingnonsensemail_ksdjfhksdfhiuhg_dsuhjfiufhsdiuhdfs@gmail.com',
            'first_name': '',
            'username': username,
            'opt_into_one_tap': False
        }

        headers = {
            'x-csrftoken': csrf_token
        }

        response2 = requests.post("https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/", headers=headers, data=data)
        code = response2.json().get('errors', {}).get('username', [{}])[0].get('code')

        if code == 'username_is_taken':
            print(f"{G}[+] instagram.com")
        else:
            print(f"{M}[-] instagram.com")


def chess1(username):
    response = requests.get(f"https://www.chess.com/callback/leagues/user-league/search/{username}")
    data = response.json()
    if data:
        username_ext = data.get("username", "N/A")    
        country = data.get("country", "N/A")
        avatar = data.get("avatar", "N/A")
        
        print(f"{G}[+] chess.com")
        print(f"{C} ├─ {G}Username : {username_ext}")
        print(f"{C} ├─ {G}Country  : {country}")
        print(f"{C} ├─ {G}Avatar   : {avatar}")
        print(f"{C} ├─ {G}Profile  : https://www.chess.com/member/{username}")
    elif response.status_code == 429:
        print(f"{R}[x] chess.com")
    else:
        print(f"{M}[-] chess.com")


def mym(username):
    headers = {
        "Host": "mym.fans",
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Accept": "application/json, text/plain, */*",
        "Sec-Ch-Ua": "\"Chromium\";v=\"135\", \"Not-A.Brand\";v=\"8\"",
        "Content-Type": "application/json;charset=UTF-8",
        "Sec-Ch-Ua-Mobile": "?0",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Origin": "https://mym.fans",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://mym.fans/app/register/email",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=1, i"
    }

    payload = {
        "username": username
    }

    response = requests.post("https://mym.fans/app/ajax/username-uniqueness", headers=headers, data=json.dumps(payload))
    data = response.json()

    try:
        if data.get("exist"):
            print(f"{G}[+] mym.fans")
        else:
            print(f"{M}[-] mym.fans")
    except Exception as e:
        print(f"{R}[x] mym.fans")


def tukif1(username):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Origin": "https://tukif.porn",
            "Referer": "https://tukif.porn/",
            "X-Requested-With": "XMLHttpRequest",
        }

        data = {
            "signup_username": username,
            "signup_password": "azerty12345",
            "signup_conf_password": "azerty12345",
            "signup_email": "email_fucked_dsfkuhiugshifguh@gmail.com"
        }

        response = requests.post("https://tukif.porn/user/signup/", headers=headers, data=urlencode(data))
        result = response.json()

        message = result.get("message", "")
        if "identifiant est déjà utilisé" in message:
            print(f"{G}[+] tukif.porn")
        else:
            print(f"{M}[-] tukif.porn")
    except Exception as e:
        print(f"{R}[x] tukif.porn")


def redtube(username):
    session = requests.Session()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Accept": "*/*",
        "Origin": "https://fr.redtube.com",
        "Referer": "https://fr.redtube.com/",
        "X-Requested-With": "XMLHttpRequest"
    }

    response = session.get("https://fr.redtube.com/", headers=headers)
    soup = BeautifulSoup(response.text, "html.parser")
    token_tag = soup.find("a", href=True, title="View Mobile Version")

    if not token_tag or "token=" not in token_tag["href"]:
        print(f"{R}[x] redtube.com")
        return

    token = token_tag["href"].split("token=")[1]

    boundary = "----WebKitFormBoundary96qCHgqLGI9yv3yj"
    post_url = f"https://fr.redtube.com/user/create_account_check?token={token}"

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="username"\r\n\r\n'
        f"{username}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="token"\r\n\r\n'
        f"{token}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="redirect"\r\n\r\n'
        f"\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="check_what"\r\n\r\n'
        f"username\r\n"
        f"--{boundary}--\r\n"
    )

    post_headers = {
        **headers,
        "Content-Type": f"multipart/form-data; boundary={boundary}"
    }

    response = session.post(post_url, headers=post_headers, data=body)

    try:
        result = response.json()
        if result.get("username") == "create_account_passed":
            print(f"{M}[-] redtube.com")
        elif result.get("username") == "create_account_failed":
            print(f"{G}[+] redtube.com")
        else:
            print(f"{R}[x] redtube.com")
    except Exception as e:
        print(f"{R}[x] redtube.com")


def chaturbate(username):
    session = requests.Session()
    get_url = "https://chaturbate.com/accounts/register/"
    get_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept-Language": "fr-FR,fr;q=0.9",
    }

    get_response = session.get(get_url, headers=get_headers)
    csrftoken = session.cookies.get("csrftoken")
    if not csrftoken:
        print(f"{R}[x] chaturbate.com")
        return

    soup = BeautifulSoup(get_response.text, "html.parser")
    csrf_form_token = soup.find("input", {"name": "csrfmiddlewaretoken"})

    boundary = "----WebKitFormBoundaryf4Dz03NNNFhwxdv8"
    post_url = "https://chaturbate.com/accounts/ajax_validate_register_form/"
    headers = {
        "User-Agent": get_headers["User-Agent"],
        "Accept": "*/*",
        "Origin": "https://chaturbate.com",
        "Referer": get_url,
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    }
    
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="csrfmiddlewaretoken"\r\n\r\n'
        f"{csrftoken}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="username"\r\n\r\n'
        f"{username}\r\n"
        f"--{boundary}--\r\n"
    )
    response = session.post(post_url, headers=headers, data=body)

    try:
        data = response.json()
        errors = data.get("errors", {})
        if "username" in errors:
            print(f"{G}[+] chaturbate.com")
        else:
            print(f"{M}[-] chaturbate.com")
    except Exception:
        print(f"{R}[x] chaturbate.com")


def candaulib1(username):
    headers = {
        "Host": "www.candaulib.com",
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Sec-Ch-Ua": "\"Chromium\";v=\"135\", \"Not-A.Brand\";v=\"8\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": "https://www.candaulib.com",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://www.candaulib.com/inscription-candaulib",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=1, i"
    }
    data = {
        "action": "inscription_chk_pseudo",
        "pseudo": username
    }
    try:
        response = requests.post("https://www.candaulib.com/mobile/action2_v5.php", headers=headers, data=data)
        text = response.text.strip()

        if text == "used":
            print(f"{G}[+] candaulib.com")
        elif text == "":
            print(f"{M}[-] candaulib.com")
        else:
            print(f"{R}[x] candaulib.com")
    except Exception as e:
        print(f"{R}[x] candaulib.com")


def lovetrans(username):
    headers = {
        "Host": "www.lovetrans.com",
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Sec-Ch-Ua": "\"Chromium\";v=\"135\", \"Not-A.Brand\";v=\"8\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": "https://www.lovetrans.com/",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=1, i"
    }
    data = {
        "action": "inscription_chk_pseudo",
        "pseudo": username
    }
    try:
        response = requests.post("https://www.lovetrans.com/action_index.php", headers=headers, data=data)
        text = response.text.strip()

        if text == "invalide":
            print(f"{G}[+] lovetrans.com")
        elif text == "":
            print(f"{M}[-] lovetrans.com")
        else:
            print(f"{R}[x] lovetrans.com")
    except Exception as e:
        print(f"{R}[x] lovetrans.com")


def sexylib(username):
    headers = {
        "Host": "www.sexylib.com",
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Sec-Ch-Ua": "\"Chromium\";v=\"135\", \"Not-A.Brand\";v=\"8\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": "https://www.sexylib.com/",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=1, i"
    }
    data = {
        "action": "inscription_chk_pseudo",
        "pseudo": username
    }
    try:
        response = requests.post("https://www.sexylib.com/mobile/action2_v5.php", headers=headers, data=data)
        text = response.text.strip()

        if text == "used":
            print(f"{G}[+] sexylib.com")
        elif text == "":
            print(f"{M}[-] sexylib.com")
        else:
            print(f"{R}[x] sexylib.com")
    except Exception as e:
        print(f"{R}[x] sexylib.com")


def gaym1(username):
    headers = {
        "Host": "www.gaym.com",
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Sec-Ch-Ua": "\"Chromium\";v=\"135\", \"Not-A.Brand\";v=\"8\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": "https://www.gaym.com/",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=1, i"
    }
    data = {
        "action": "inscription_chk_pseudo",
        "pseudo": username
    }
    try:
        response = requests.post("https://www.gaym.com/action_index.php", headers=headers, data=data)
        text = response.text.strip()

        if text == "invalide":
            print(f"{G}[+] gaym.com")
        elif text == "":
            print(f"{M}[-] gaym.com")
        else:
            print(f"{R}[x] gaym.com")
    except Exception as e:
        print(f"{R}[x] gaym.com")


def lesrebeux1(username):
    headers = {
        "Host": "www.lesrebeus.com",
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Sec-Ch-Ua": "\"Chromium\";v=\"135\", \"Not-A.Brand\";v=\"8\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": "https://www.lesrebeus.com/",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=1, i"
    }
    data = {
        "action": "inscription_chk_pseudo",
        "pseudo": username
    }
    try:
        response = requests.post("https://www.lesrebeus.com/action_index.php", headers=headers, data=data)
        text = response.text.strip()

        if text == "invalide":
            print(f"{G}[+] lesrebeus.com")
        elif text == "":
            print(f"{M}[-] lesrebeus.com")
        else:
            print(f"{R}[x] lesrebeus.com")
    except Exception as e:
        print(f"{R}[x] lesrebeus.com")


def darkforums(username):
    headers = {
        "accept": "application/json, text/javascript, */*; q=0.01",
        "accept-encoding": "identity",
        "accept-language": "fr-FR,fr;q=0.9",
        "priority": "u=1, i",
        "referer": "https://darkforums.st/member.php",
        "sec-ch-ua": '"Brave";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "sec-gpc": "1",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "x-requested-with": "XMLHttpRequest"
    }

    response = requests.get(
        f"https://darkforums.st/xmlhttp.php?action=get_users&query={username}", headers=headers
    )

    try:
        users = response.json()
        if users:
            print(f"{G}[+] darkforums.st")
            for user in users:
                print(f"{C} ├─ {G}UID : {user['uid']}, Username : {user['id']}")
        else:
            print(f"{M}[-] darkforums.st")
    except requests.exceptions.JSONDecodeError:
        print(f"{R}[x] darkforums.st")


def cracked(username):
    headers = {
        "accept": "application/json, text/javascript, */*; q=0.01",
        "accept-encoding": "identity",
        "accept-language": "fr-FR,fr;q=0.9",
        "priority": "u=1, i",
        "referer": "https://cracked.sh/member.php",
        "sec-ch-ua": '"Brave";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "sec-gpc": "1",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "x-requested-with": "XMLHttpRequest"
    }

    response = requests.get(
        f"https://cracked.sh/xmlhttp.php?action=get_users&query={username}", headers=headers
    )

    try:
        users = response.json()
        if users:
            print(f"{G}[+] cracked.sh")
            for user in users:
                print(f"{C} ├─ {G}UID : {user['uid']}, Username : {user['id']}")
        else:
            print(f"{M}[-] cracked.sh")
    except requests.exceptions.JSONDecodeError:
        print(f"{R}[x] cracked.sh")


def nouslibertin1(username):
    
    print(username)
    if not (4 <= len(username) <= 15):
        print(f"{M}[-] placelibertine.com")
        return

    if not username[0].isalpha():
        print(f"{M}[-] placelibertine.com")
        return

    if not username[0].isupper():
        username = username[0].upper() + username[1:]
    
    print(username)
    headers = {
        "Host": "www.placelibertine.com",
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Sec-Ch-Ua": "\"Chromium\";v=\"135\", \"Not-A.Brand\";v=\"8\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": "https://www.placelibertine.com",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://www.placelibertine.com/",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }
    data = {
        "Inscription[pseudo]": username
    }
    
    response = requests.post("https://www.placelibertine.com/fr/inscription-1", headers=headers, data=data)
    if response.status_code == 200:
        try:
            result = response.json()
            if "pseudo" in result.get("error", {}):
                print(f"{G}[+] placelibertine.com")
            else:
                print(f"{M}[-] placelibertine.com")
        except Exception as e:
            print(f"{R}[x] placelibertine.com")
    else:
        print(f"{R}[x] placelibertine.com")




def init_search(target, what):
    if what == "email":
        paypal(target)
        ebay(target)
        vivino(target)
        academia(target)
        adobe_check(target)
        trello(target)
        spotify(target)
        deliveroo(target)
        apple(target)
        gravatar(target)
        strava(target)
        twitter1(target)
        instagram(target)
        chess(target)
        lastpass(target)
        deezer(target)
        duolingo(target)
        mym1(target)
        pornhub(target)
        xnxx(target)
        xvideos(target)
        youporn(target)
        tukif(target)
        redtube1(target)
        lespompeurs(target)
        candaulib(target)
        lovetrans1(target)
        sexylib1(target)
        gaym(target)
        lesrebeux(target)
        nouslibertin(target)
        
    elif what == "phone":
        apple(target)
        pagesjaunes(target)
        
    elif what == "username":
        gravatar1(target)
        twitter(target)
        instagram1(target)
        chess1(target)
        mym(target)
        tukif1(target)
        redtube(target)
        chaturbate(target)
        candaulib1(target)
        lovetrans(target)
        sexylib(target)
        gaym1(target)
        lesrebeux1(target)
        darkforums(target)
        cracked(target)
        nouslibertin1(target)
