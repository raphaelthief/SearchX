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
            if "adresse n'est pas utilisable" in result.get("results", {}).get("error_message"):
                print(f"{M}[-] lespompeurs.com")
            else:
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


def placelibertine(email):
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


def nouslib(email):
    session = requests.Session()
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'
    }

    url_step1 = 'https://www.nouslib.com/inscription'
    response1 = session.get(url_step1, headers=headers)
    soup1 = BeautifulSoup(response1.text, 'html.parser')

    authenticity_token_1 = soup1.find('input', {'name': 'authenticity_token'})['value']
    #print("Token 1:", authenticity_token_1)

    url_post_step1 = 'https://www.nouslib.com/inscription/step/1'
    data_step1 = {
        '_method': 'patch',
        'authenticity_token': authenticity_token_1,
        'registration[user_type_id]': '2',
        'registration[seek_couple]': '1',
        'registration[seek_female]': '0',
        'registration[seek_male]': '0',
        'registration[seek_shemale]': '0',
        'registration[f_age]': '19',
        'registration[m_age]': '',
        'registration[username]': 'testsdfsdf',
        'registration[country_id]': '1',
        'registration[zip_code]': '75001',
        'registration[city_id]': '118360'
    }
    response2 = session.post(url_post_step1, data=data_step1, headers=headers)
    
    if not response2.status_code == 422:
        print(f"{R}[x] nouslib.com")
        return
    
    soup2 = BeautifulSoup(response2.text, 'html.parser')

    authenticity_token_2 = soup2.find('input', {'name': 'authenticity_token'})['value']
    #print("Token 2:", authenticity_token_2)

    url_post_step2 = 'https://www.nouslib.com/inscription/step/2'
    data_step2 = {
        '_method': 'patch',
        'authenticity_token': authenticity_token_2,
        'registration[email]': email,
        'registration[password]': '',
        'registration[conditions]': '1',
        'registration[settings_email_other]': '0'
    }
    response3 = session.post(url_post_step2, data=data_step2, headers=headers)

    if response3.status_code == 422:
        if "est déjà utilisé." in response3.text:
            print(f"{G}[+] nouslib.com")
        else:
            print(f"{M}[-] nouslib.com")
    else:
        print(f"{R}[x] nouslib.com")
        

def espritlib(email):
    try:
        response = requests.get(f"http://www.espritlib.com/v2/verif_email.php?email={email}")
        text = response.text.strip()

        if text == "1":
            print(f"{G}[+] espritlib.com")
        elif text == "2":
            print(f"{M}[-] espritlib.com")
        else:
            print(f"{R}[x] espritlib.com")
    except Exception as e:
        print(f"{R}[x] espritlib.com")


def vivaflirt(email):
    try:
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Referer": "https://www.vivaflirt.fr/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
            "Accept": "application/json, text/javascript, */*; q=0.01"
        }
        
        response = requests.get(f"https://www.vivaflirt.fr/members/ajax_check_email?email={email}", headers=headers)
        text = response.text.strip()
        data = response.json()

        if data.get("is_success") == 0 and data.get("error", {}).get("code") == 106:
            print(f"{G}[+] vivaflirt.fr")
        elif data.get("is_success") == 1:
            print(f"{M}[-] vivaflirt.fr")
        else:
            print(f"{R}[x] vivaflirt.fr")
    except Exception as e:
        print(f"{R}[x] vivaflirt.fr")


def hypnotube(email):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": "https://hypnotube.com/signup",
            "Origin": "https://hypnotube.com",
        }

        data = {
            "signup_username": "",
            "signup_password": "",
            "signup_email": email,
            "captchaaa": "",
            "signup_tos": "",
            "Submit": ""
        }

        response = requests.post("https://hypnotube.com/signup", headers=headers, data=data)

        # Analyse HTML avec BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')

        # Recherche du message d'erreur
        notification = soup.find('div', class_='notification error')
        if notification:
            error_text = notification.get_text(separator=' ').strip()

            if "email" in error_text.lower():
                print(f"{G}[+] hypnotube.com")
            else:
                print(f"{M}[-] hypnotube.com")
        else:
            print(f"{R}[x] hypnotube.com")
    except Exception as e:
        print(f"{R}[x] hypnotube.com")


def zapier(email):
    session = requests.Session()
    common_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Referer": "https://zapier.com/app/login",
        "Origin": "https://zapier.com",
        "Accept": "*/*"
    }
    session.get("https://zapier.com/app/login", headers=common_headers)
    csrf_response = session.get("https://zapier.com/api/v3/csrf", headers=common_headers)

    csrf_token = session.cookies.get('csrftoken')
    if not csrf_token:
        print(f"{R}[x] zapier.com")
        return

    login_headers = {
        **common_headers,
        "Content-Type": "application/json;charset=utf-8",
        "Accept": "application/json",
        "X-Csrftoken": csrf_token,
        "X-Requested-With": "XMLHttpRequest"
    }
    
    login_payload = {
        "email": email
    }
    
    login_response = session.post(
        "https://zapier.com/api/v3/login",
        headers=login_headers,
        json=login_payload
    )

    if login_response.status_code == 401:
        try:
            data = login_response.json()
            if "errors" in data:
                message_done = False
                for error in data["errors"]:
                    for field in error.get("fields", []):
                        key = field.get("key")
                        message = field.get("message").lower()

                        if key == "email" and "doesn" in message and "exist" in message:
                            print(f"{M}[-] zapier.com")
                            message_done = True
                        elif key == "password" and "incorrect" in message:
                            print(f"{G}[+] zapier.com")
                            message_done = True

                if not message_done:
                    print(f"{R}[x] zapier.com")
            else:
                print(f"{G}[+] zapier.com")
        except ValueError:
            print(f"{R}[x] zapier.com")
    else:
        print(f"{R}[x] zapier.com")



############################## PHONE ##############################

def apple1(phone):
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
    try:
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " 
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/123.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://www.chess.com/",
            "Origin": "https://www.chess.com",
            "Connection": "keep-alive"
        }
        
        
        response = requests.get(f"https://www.chess.com/callback/leagues/user-league/search/{username}", headers=headers)
        if response.status_code == 200:
            try:
                data = response.json()
                username_ext = data.get("username", "N/A")    
                country = data.get("country", "N/A")
                avatar = data.get("avatar", "N/A")
                
                print(f"{G}[+] chess.com")
                print(f"{C} ├─ {G}Username : {username_ext}")
                print(f"{C} ├─ {G}Country  : {country}")
                print(f"{C} ├─ {G}Avatar   : {avatar}")
                print(f"{C} ├─ {G}Profile  : https://www.chess.com/member/{username}")
            except ValueError:
                print(f"{M}[-] chess.com: Invalid JSON in primary response")
        elif response.status_code == 429:
            print(f"{R}[x] chess.com (Rate limited)")
        else:
            response2 = requests.get(f"https://api.chess.com/pub/player/{username}", headers=headers)
            if response2.status_code == 200:
                try:
                    data2 = response2.json()
                    username_ext = data2.get("username", "N/A")    
                    country = data2.get("country", "N/A")
                    ID = data2.get("player_id", "N/A")
                    print(f"{G}[+] chess.com")
                    print(f"{C} ├─ {G}Username : {username_ext}")
                    print(f"{C} ├─ {G}Country  : {country}")
                    print(f"{C} ├─ {G}ID       : {ID}")
                    print(f"{C} ├─ {G}Profile  : https://www.chess.com/member/{username}")
                except ValueError:
                    print(f"{R}[x] chess.com (Capcha)")
            elif response2.status_code == 429:
                print(f"{R}[x] chess.com (Rate limited)")
            elif response2.status_code == 404:
                print(f"{M}[-] chess.com")
            else:
                print(f"{R}[x] chess.com (Capcha)")
    except requests.RequestException as e:
        print(f"{R}[x] chess.com")


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
    except ValueError:
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
    except ValueError:
        print(f"{R}[x] cracked.sh")


def placelibertine1(username):
    if not (4 <= len(username) <= 15):
        print(f"{M}[-] placelibertine.com")
        return

    if not username[0].isalpha():
        print(f"{M}[-] placelibertine.com")
        return

    if not username[0].isupper():
        username = username[0].upper() + username[1:]
    
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


def gareauxlibertins(username):
    headers = {
        "Host": "www.gareauxlibertins.com",
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Sec-Ch-Ua": "\"Chromium\";v=\"135\", \"Not-A.Brand\";v=\"8\"",
        "Content-Type": "application/x-www-form-urlencoded",
        "Sec-Ch-Ua-Mobile": "?0",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Origin": "https://www.gareauxlibertins.com",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://www.gareauxlibertins.com/inscription.php",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=1, i",
        "Connection": "keep-alive"
    }

    data = {
        "val_1": "pseudo",
        "val_2": username,
        "val_3": "6",
        "val_4": "",
        "val_5": "undefined"
    }

    response = requests.post("https://www.gareauxlibertins.com/include/membres/check.php", headers=headers, data=data)

    match = re.search(r'\$\(\"\#erreur_pseudo\"\)\.html\(\'(.*?)\'\);', response.text)

    if match:
        contenu = match.group(1).strip()
        if contenu:
            print(f"{G}[+] gareauxlibertins.com")
        else:
            print(f"{M}[-] gareauxlibertins.com")
    else:
        print(f"{R}[x] gareauxlibertins.com")
        

def adultfriendfinder(username):
    response = requests.get(f"https://adultfriendfinder.com/p/register.cgi?action=check_handle&REG_handle={username}&do_json=1&sitelist=ffadult&rid=4399401002")
    data = response.json()
    if data.get("available") == 1:
        print(f"{M}[-] adultfriendfinder.com")
    elif data.get("available") == 0:
        print(f"{G}[+] adultfriendfinder.com")
    else:
        print(f"{R}[x] adultfriendfinder.com")

def vinted(username):
    session = requests.Session()

    headers = {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
    }

    initial_url = "https://www.vinted.com/"
    initial_response = session.get(initial_url, headers=headers)

    api_url = f"https://www.vinted.com/api/v2/users/{username}"
    api_response = session.get(api_url, headers=headers)

    if api_response.status_code == 200:
        print(f"{G}[+] vinted.com")
        infos = api_response.json().get("user", {})

        print(f"{C} ├─ {G}Id                :{Y} "+str(infos.get("id", "N/A")))
        print(f"{C} ├─ {G}Login             :{Y} "+str(infos.get("login", "N/A")))
        print(f"{C} ├─ {G}Anon id           :{Y} "+str(infos.get("anon_id", "N/A")))
        print(f"{C} ├─ {G}Profile url       :{Y} "+str(infos.get("profile_url", "N/A")))
        print(f"{C} ├─ {G}Is online         :{Y} "+str(infos.get("is_online", "N/A")))
        print(f"{C} ├─ {G}Is account banned :{Y} "+str(infos.get("is_account_banned", "N/A")))
        print(f"{C} ├─ {G}Account ban date  :{Y} "+str(infos.get("account_ban_date", "N/A")))
        print(f"{C} ├─ {G}Permanant ban     :{Y} "+str(infos.get("is_account_ban_permanent", "N/A")))
        
        print(f"{C} ├─ {G}Email             :{Y} "+str(infos.get("email", "N/A")))
        print(f"{C} ├─ {G}Facebook user id  :{Y} "+str(infos.get("facebook_user_id", "N/A")))
        print(f"{C} ├─ {G}Birthday          :{Y} "+str(infos.get("birthday", "N/A")))
        print(f"{C} ├─ {G}Item count        :{Y} "+str(infos.get("item_count", "N/A")))
        print(f"{C} ├─ {G}Followers         :{Y} "+str(infos.get("followers_count", "N/A")))
        print(f"{C} ├─ {G}Following         :{Y} "+str(infos.get("following_count", "N/A")))
        print(f"{C} ├─ {G}Last logged on    :{Y} "+str(infos.get("last_loged_on_ts", "N/A")))
        print(f"{C} ├─ {G}City              :{Y} "+str(infos.get("city", "N/A")))
        print(f"{C} ├─ {G}Country           :{Y} "+str(infos.get("country_title", "N/A")))

        photo = infos.get("photo")
        if photo:
            print(f"{C} ├─ {G}Profile picture   :{Y} "+str(photo.get("url", "N/A")))
        else:
            print(f"{C} ├─ {G}Profile picture   :{Y} None")
        
        print(f"{C} └─ {G}Verification types")
        for v_type, v_info in infos.get("verification", {}).items():
            line = f"{v_type} "
            for k, val in v_info.items():
                print(f"{C}    ├─ {G}{line} --> {k} :{Y} {val}")


    elif api_response.status_code == 404:
        print(f"{M}[-] vinted.com")
    
    else:
        print(f"{R}[x] vinted.com")


def vivino1(username):
    headers = {
        "Host": "api.vivino.com",
        "Sec-Ch-Ua": '"Chromium";v="135", "Not-A.Brand";v="8"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=0, i"
    }
    
    try:
        response = requests.get(f"https://api.vivino.com/users/{username}", headers=headers)
        if response.status_code == 404:
            print(f"{M}[-] vivino.com")
            return
            
        response.raise_for_status()
        data = response.json()

        if "error" in data:
            print(f"{M}[-] vivino.com")
        else:
            print(f"{G}[+] vivino.com")
            print(f"{C} ├─ {G}Alias             :{Y} {data['alias']}")
            print(f"{C} ├─ {G}ID                :{Y} {data['id']}")
            print(f"{C} ├─ {G}Profile image     :{Y} {data['image']['location']}")
            
            print(f"{C} ├─ {G}Bio               :{Y} {data.get('bio', 'N/A')}")
            print(f"{C} ├─ {G}Website           :{Y} {data.get('website', 'N/A')}")

            address = data.get('address', {})
            print(f"{C} ├─ {G}Country           :{Y} {address.get('country', 'N/A')}")
            print(f"{C} │   ├─ {G}City          :{Y} {address.get('city', 'N/A')}")
            print(f"{C} │   ├─ {G}Zip           :{Y} {address.get('zip', 'N/A')}")
            print(f"{C} │   ├─ {G}Street        :{Y} {address.get('street', 'N/A')}")
            print(f"{C} │   ├─ {G}State         :{Y} {address.get('state', 'N/A')}")
            print(f"{C} │   ├─ {G}Phone         :{Y} {address.get('phone', 'N/A')}")
            print(f"{C} │   ├─ {G}Company       :{Y} {address.get('company', 'N/A')}")
            print(f"{C} │   └─ {G}VAT Number    :{Y} {address.get('vat_number', 'N/A')}")

            stats = data.get('statistics', {})
            print(f"{C} ├─ {G}Followers         :{Y} {stats.get('followers_count', 0)}")
            print(f"{C} ├─ {G}Following         :{Y} {stats.get('followings_count', 0)}")
            print(f"{C} ├─ {G}Ratings given     :{Y} {stats.get('ratings_count', 0)}")
            print(f"{C} ├─ {G}Ratings total sum :{Y} {stats.get('ratings_sum', 0)}")
            print(f"{C} ├─ {G}Reviews           :{Y} {stats.get('reviews_count', 0)}")
            print(f"{C} ├─ {G}Purchases         :{Y} {stats.get('purchase_order_count', 0)}")
            print(f"{C} ├─ {G}Wishlist items    :{Y} {stats.get('wishlist_count', 0)}")
            print(f"{C} └─ {G}Activity stories  :{Y} {stats.get('activity_stories_count', 0)}")
            
    except Exception as e:
        print(f"{R}[x] vivino.com")

def hypnotube1(username):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": "https://hypnotube.com/signup",
            "Origin": "https://hypnotube.com",
        }

        data = {
            "signup_username": username,
            "signup_password": "",
            "signup_email": "",
            "captchaaa": "",
            "signup_tos": "",
            "Submit": ""
        }

        response = requests.post("https://hypnotube.com/signup", headers=headers, data=data)

        # Analyse HTML avec BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')

        # Recherche du message d'erreur
        notification = soup.find('div', class_='notification error')
        if notification:
            error_text = notification.get_text(separator=' ').strip()

            if "username" in error_text.lower():
                print(f"{G}[+] hypnotube.com")
            else:
                print(f"{M}[-] hypnotube.com")
        else:
            print(f"{R}[x] hypnotube.com")
    except Exception as e:
        print(f"{R}[x] hypnotube.com")


def stripchat(username):
    headers = {
        "Host": "fr.stripchat.com",
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Sec-Ch-Ua": "\"Chromium\";v=\"135\", \"Not-A.Brand\";v=\"8\"",
        "Front-Version": "11.1.72",
        "Content-Type": "application/json",
        "Sec-Ch-Ua-Mobile": "?0",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://fr.stripchat.com/",
        "Accept-Encoding": "gzip, deflate, br",
    }

    response = requests.get(f"https://fr.stripchat.com/api/front/users/checkUsername?username={username}", headers=headers)

    if response.status_code == 200:
        if response.text.strip() == "[]":
            print(f"{M}[-] stripchat.com")
        else:
            print(f"{R}[x] stripchat.com")
    elif response.status_code == 400:
        if "utilisateur existe" in response.text:
            print(f"{G}[+] stripchat.com")
            
            response = requests.get(f"https://fr.stripchat.com/api/front/v2/users/username/{username}", headers=headers)
            data = response.json()
            item = data["item"]
            ID = item['id']
            
            print(f"{C} ├─ {G}ID                   : {Y}{item['id']}")
            print(f"{C} ├─ {G}isAdmin              : {Y}{item['isAdmin']}")
            print(f"{C} ├─ {G}isRegular            : {Y}{item['isRegular']}")
            print(f"{C} ├─ {G}isExGreen            : {Y}{item['isExGreen']}")
            print(f"{C} ├─ {G}isUltimate           : {Y}{item['isUltimate']}")
            print(f"{C} ├─ {G}isGreen              : {Y}{item['isGreen']}")
            print(f"{C} ├─ {G}isModel              : {Y}{item['isModel']}")
            print(f"{C} ├─ {G}isStudio             : {Y}{item['isStudio']}")
            print(f"{C} ├─ {G}isSupport            : {Y}{item['isSupport']}")
            print(f"{C} ├─ {G}isDeleted            : {Y}{item['isDeleted']}")
            print(f"{C} ├─ {G}isBlocked            : {Y}{item['isBlocked']}")
            print(f"{C} ├─ {G}isOnline             : {Y}{item['isOnline']}")
            print(f"{C} ├─ {G}isPermanentlyBlocked : {Y}{item['isPermanentlyBlocked']}")
            print(f"{C} ├─ {G}hasAdminBadge        : {Y}{item['hasAdminBadge']}")
            print(f"{C} ├─ {G}hasVrDevice          : {Y}{item['hasVrDevice']}")
            
            response2 = requests.get(f"https://fr.stripchat.com/api/front/v2/users/{ID}/profile", headers=headers)
            data2 = response2.json()
            item2 = data2["item"]
            
            print(f"{C} ├─ {G}name                 : {Y}{item2['name']}")
            print(f"{C} ├─ {G}birthDate            : {Y}{item2['birthDate']}")
            print(f"{C} ├─ {G}country              : {Y}{item2['country']}")
            print(f"{C} ├─ {G}region               : {Y}{item2['region']}")
            print(f"{C} ├─ {G}city                 : {Y}{item2['city']}")
            print(f"{C} ├─ {G}cityId               : {Y}{item2['cityId']}")
            print(f"{C} ├─ {G}languages            : {Y}{item2['languages']}")
            print(f"{C} ├─ {G}interestedIn         : {Y}{item2['interestedIn']}")
            print(f"{C} ├─ {G}bodyType             : {Y}{item2['bodyType']}")
            print(f"{C} ├─ {G}specifics            : {Y}{item2['specifics']}")
            print(f"{C} ├─ {G}ethnicity            : {Y}{item2['ethnicity']}")
            print(f"{C} ├─ {G}hairColor            : {Y}{item2['hairColor']}")
            print(f"{C} ├─ {G}eyeColor             : {Y}{item2['eyeColor']}")
            print(f"{C} ├─ {G}subculture           : {Y}{item2['subculture']}")
            print(f"{C} ├─ {G}description          : {Y}{item2['description']}")
            print(f"{C} ├─ {G}amazonWishlist       : {Y}{item2['amazonWishlist']}")
            print(f"{C} ├─ {G}age                  : {Y}{item2['age']}")
            print(f"{C} ├─ {G}interests            : {Y}{item2['interests']}")
            print(f"{C} ├─ {G}gender               : {Y}{item2['gender']}")
            print(f"{C} ├─ {G}avatarUrl            : {Y}{item2['avatarUrl']}")
            print(f"{C} ├─ {G}avatarUrlOriginal    : {Y}{item2['avatarUrlOriginal']}")
            print(f"{C} └─ {G}createdAt            : {Y}{item2['createdAt']}")
            
        else:
            print(f"{M}[-] stripchat.com")
    else:
        print(f"{R}[x] stripchat.com")
        

def duolingo1(username):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Accept": "application/json",
    }

    response = requests.get(f"https://www.duolingo.com/2017-06-30/users?username={username}", headers=headers)

    if response.status_code == 200:
        data = response.json()
        if data["users"]:
            print(f"{G}[+] duolingo.com")
            user = data["users"][0]
            print(f"{C} ├─ {G}ID                            : {Y}{user['id']}")
            print(f"{C} ├─ {G}Username                      : {Y}{user['username']}")
            print(f"{C} ├─ {G}Name                          : {Y}{user.get('name', '')}")
            print(f"{C} ├─ {G}From Language                 : {Y}{user.get('fromLanguage', '')}")
            print(f"{C} ├─ {G}Learning Language             : {Y}{user.get('learningLanguage', '')}")
            print(f"{C} ├─ {G}Total XP                      : {Y}{user.get('totalXp', 0)}")
            print(f"{C} ├─ {G}Streak                        : {Y}{user.get('streak', 0)}")
            print(f"{C} ├─ {G}Bio                           : {Y}{user.get('bio', '')}")
            print(f"{C} ├─ {G}Location                      : {Y}{user.get('location', '')}")
            print(f"{C} ├─ {G}Email Verified                : {Y}{user.get('emailVerified', False)}")
            print(f"{C} ├─ {G}Has Plus                      : {Y}{user.get('hasPlus', False)}")
            print(f"{C} ├─ {G}Profile Pic URL               : {Y}{user.get('picture', '')}")
            print(f"{C} ├─ {G}Creation Date (timestamp)     : {Y}{user.get('creationDate')}")
            print(f"{C} ├─ {G}Beta Status                   : {Y}{user.get('betaStatus')}")
            print(f"{C} ├─ {G}Motivation                    : {Y}{user.get('motivation')}")
            print(f"{C} ├─ {G}Acquisition Survey Reason     : {Y}{user.get('acquisitionSurveyReason')}")
            print(f"{C} ├─ {G}Has Facebook ID               : {Y}{user.get('hasFacebookId')}")
            print(f"{C} ├─ {G}Has Google ID                 : {Y}{user.get('hasGoogleId')}")
            print(f"{C} ├─ {G}Has Phone Number              : {Y}{user.get('hasPhoneNumber')}")
            print(f"{C} ├─ {G}Should Connect Phone Number   : {Y}{user.get('shouldForceConnectPhoneNumber')}")
            print(f"{C} ├─ {G}Can Use Moderation Tools      : {Y}{user.get('canUseModerationTools')}")
            print(f"{C} ├─ {G}Shake to Report Enabled       : {Y}{user.get('shakeToReportEnabled')}")
            print(f"{C} ├─ {G}Current Course ID             : {Y}{user.get('currentCourseId')}")
            print(f"{C} ├─ {G}Email Verified                : {Y}{user.get('emailVerified')}")
            print(f"{C} ├─ {G}Classroom Leaderboards Enabled: {Y}{user.get('classroomLeaderboardsEnabled')}")
            print(f"{C} ├─ {G}Roles                         : {Y}{user.get('roles', [])}")
            print(f"{C} ├─ {G}Joined Classroom IDs          : {Y}{user.get('joinedClassroomIds', [])}")
            print(f"{C} ├─ {G}Observed Classroom IDs        : {Y}{user.get('observedClassroomIds', [])}")
            print(f"{C} ├─ {G}Privacy Settings              : {Y}{user.get('privacySettings', [])}")
            print(f"{C} ├─ {G}China Moderation Records      : {Y}{user.get('chinaUserModerationRecords', [])}")
            print(f"{C} ├─ {G}Global Ambassador Status      : {Y}{user.get('globalAmbassadorStatus', {})}")
            print(f"{C} ├─ {G}Achievements                  : {Y}{user.get('achievements', [])}")
            print(f"{C} ├─ {G}Achievements (legacy)         : {Y}{user.get('_achievements', [])}")
            print(f"{C} ├─ {G}Live Ops Features             : {Y}{user.get('liveOpsFeatures', [])}")
            print(f"{C} ├─ {G}Profile Country               : {Y}{user.get('profileCountry')}")
            print(f"{C} ├─ {G}Streak Data                   : {Y}{user.get('streakData', {})}")
            
            print(f"{C} ├─ {G}Courses:")
            for course in user.get("courses", []):
                print(f"{C} │    ├─ {G}Title           : {Y}{course.get('title')}")
                print(f"{C} │    ├─ {G}Language        : {Y}{course.get('learningLanguage')}")
                print(f"{C} │    ├─ {G}From Language   : {Y}{course.get('fromLanguage')}")
                print(f"{C} │    ├─ {G}XP              : {Y}{course.get('xp')}")
                print(f"{C} │    ├─ {G}Crowns          : {Y}{course.get('crowns')}")
                print(f"{C} │    ├─ {G}Health Enabled  : {Y}{course.get('healthEnabled')}")
                print(f"{C} │    ├─ {G}Author ID       : {Y}{course.get('authorId')}")
                print(f"{C} │    └─ {G}Course ID       : {Y}{course.get('id')}")
            print(f"{C} └─ {G}End of user data")
        else:
            print(f"{M}[-] duolingo.com")
    else:
        print(f"{R}[x] duolingo.com")





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
        placelibertine(target)
        nouslib(target)
        espritlib(target)
        vivaflirt(target)
        hypnotube(target)
        zapier(target)
        
    elif what == "phone":
        apple1(target)
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
        placelibertine1(target)
        gareauxlibertins(target)
        adultfriendfinder(target)
        vinted(target)
        vivino1(target)
        hypnotube1(target)
        stripchat(target)
        duolingo1(target)
