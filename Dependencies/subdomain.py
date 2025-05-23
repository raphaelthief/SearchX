import requests, json, time, warnings
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from colorama import init, Fore, Style

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

init()  # Init colorama for colored text in terminal

KEYWORDS = [
    'admin', 'api', 'file', 'intranet', 'pwd', 'pass',
    'config', 'dev', 'test', 'staging', 'panel', 'secret',
    'management', 'cms', 'user', 'private', 'server', 
    'cloud', 'settings', 'control', 'portal', 
    'ssh', 'ftp', 'database', 'internal', 'adminpanel',
    'superadmin', 'console', 'access', 'system', 'account', 
    'adminer', 'wordpress', 'cpanel', 'git', 'svn', 
    'pma', 'phpmyadmin', 'login', 'password', 'root', 
    'shell', 'vnc', 'docker', 'docker-compose', 'remote', 
    'vault', 'repository', 'secure', 'ssl', 'auth', 
    'manage', 'configurator', 'monitor', 'dashboard', 'adminaccess', 
    'backend', 'frontdoor', 'support', 'helpdesk', 'cloudadmin',
    'apiaccess', 'internal-api', 'sandbox', 'devops', 'ci-cd', 
    'gitlab', 'jenkins', 'deployment', 'webhooks', 'cron', 
    'backup', 'vpn', 'token', 'oauth', 'sso', 'loginportal',
    '2fa', 'mfa', 'security', 'credentials', 'reset', 'radius',
    'key', 'apikey', 'session', 'jwt', 'signin', 'recovery',
    'logout', 'change-password', 'unlock', 'identity', 'idp',
    'authenticator', 'authorization', 'authserver', 'auth-api'    
]


def highlight_keywords(text, keywords):
    for kw in keywords:
        if kw.lower() in text.lower():
            text = text.replace(kw, f"{Fore.RED}{kw}{Fore.CYAN}")
            text = text.replace(kw.capitalize(), f"{Fore.RED}{kw.capitalize()}{Fore.CYAN}")
    return text


def detect_login_page(content):
    login_keywords = ["login", "connexion", "password", "sign in", "authentication"]
    soup = BeautifulSoup(content, "html.parser")

    if soup.title and any(keyword in soup.title.text.lower() for keyword in login_keywords):
        return True

    if soup.find("input", {"type": "password"}) or soup.find("form", {"action": lambda x: x and "login" in x.lower()}):
        return True

    return False


# Target subdomains enum
def subreponse(domain, api_key):
    print(f"{Fore.YELLOW}[!] Subdomains for {Fore.CYAN}{domain}")
    with open(api_key, 'r') as f:
        token = f.read().strip()
        if token == '':
            pass
        else:    
            print(f"{Fore.YELLOW}[!] Source : https://www.virustotal.com/")
            
            url = 'https://www.virustotal.com/vtapi/v2/domain/report'
            params = {'apikey':token,'domain':domain}
            try:
                response = requests.get("https://www.virustotal.com/vtapi/v2/domain/report", params=params)
                jdata = response.json()
                domains = sorted(jdata['subdomains'])

                for domainz in domains:

                    #print(f"{Fore.GREEN}[+] {Fore.CYAN}{domainz}")
                    highlighted = highlight_keywords(domainz, KEYWORDS)
                    print(f"{Fore.GREEN}[+] {Fore.CYAN}{highlighted}")
                print("")
            except(KeyError):
                print(f"{Fore.MAGENTA}[!] {Fore.GREEN}No subdomains found for {Fore.YELLOW}{domain}\n")
                pass
            except(requests.ConnectionError):
                print(f"{Fore.RED}[!] Rate limit error")
                pass
                
    print(f"{Fore.YELLOW}[!] Source : https://crt.sh/")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }    
    
    url = f"https://crt.sh/?q={domain}"
    try:

     
        
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"{Fore.MAGANTA}[Error] {Fore.RED}Request error to {url} : {e}")
        return

    soup = BeautifulSoup(response.text, 'html.parser')
    
    
    try:
        table = soup.find_all('table')[1] 
        rows = table.find_all('tr')[1:]  
    except IndexError:
        print(f"{Fore.MAGANTA}[Error] {Fore.RED}No valid data found on {url}")
        return    

    certificates = {}
    for row in rows:
        cols = row.find_all('td')
        if len(cols) >= 6:
            cert_id = cols[0].text.strip()
            logged_at = cols[1].text.strip()
            not_before = cols[2].text.strip()
            not_after = cols[3].text.strip()
            common_name = cols[4].text.strip()

            if common_name not in certificates or logged_at > certificates[common_name]['logged_at']:
                certificates[common_name] = {
                    "cert_id": cert_id,
                    "logged_at": logged_at,
                    "not_before": not_before,
                    "not_after": not_after,
                    "common_name": common_name
                }

    if not certificates:
        print(f"{Fore.MAGENTA}[!] {Fore.GREEN}No subdomains found for {Fore.YELLOW}{domain}")
        return

    print("-" * 50)
    
    for cert in certificates.values():
        test_url = f"http://{cert['common_name']}"  # HTTP default     
        statuscode = "N/A"  # init statuscode
        try:
            test_response = requests.get(test_url, headers=headers, timeout=5)
            status = test_response.status_code
            statuscode = test_response.status_code
            
            if status == 403 or status == 200:
                if detect_login_page(test_response.text):
                    status = f"login page [{Fore.RED}{statuscode}{Fore.GREEN}]"            
            
        except requests.exceptions.Timeout as e:
            status = f"Timedout [{Fore.RED}{statuscode}{Fore.GREEN}]"

            test_url = "/"
        except requests.exceptions.ConnectionError as e:
            if "getaddrinfo failed" in str(e):
                status = f"DNS resolution failed [{Fore.RED}{statuscode}{Fore.GREEN}]"

            else:
                status = f"Connection error [{Fore.RED}{statuscode}{Fore.GREEN}]"

            test_url = "/"
        except requests.exceptions.RequestException as e:
            status = f"Unexpected error [{Fore.RED}{statuscode}{Fore.GREEN}]"

            test_url = "/"
            
        #print(f"{Fore.GREEN}[+] {Fore.YELLOW}Common Name    : {Fore.CYAN}{cert['common_name']}")
        highlighted_cn = highlight_keywords(cert['common_name'], KEYWORDS)
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Common Name    : {Fore.CYAN}{highlighted_cn}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Logged At      : {Fore.GREEN}{cert['logged_at']}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}More Infos     : {Fore.GREEN}https://crt.sh/?id={cert['cert_id']}{Fore.YELLOW}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Satus          : {Fore.GREEN}{status}{Fore.YELLOW}")
        

        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Direct URL     : {Fore.GREEN}{test_url}{Fore.YELLOW}")
        print("-" * 50)
        
        time.sleep(0.5)
        
