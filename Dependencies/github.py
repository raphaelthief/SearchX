import requests, os

# colorama
from colorama import init, Fore, Style

init() # Init colorama

token = None
headers = None


def githubusername(uname):
    token_file_path = 'Tokens/github_token.txt'
    global token, headers
    if os.path.exists(token_file_path):
        with open(token_file_path, 'r') as file:
            token_content = file.read().strip()
            if token_content:  
                token = token_content
    headers = {"Authorization": f"token {token}"} if token else {}
    
    check_rate_limit(uname, headers)


def check_rate_limit(uname, headers):
    url = "https://api.github.com/rate_limit"
    response = requests.get(url, headers=headers)
    rate_limit = response.json()
    remaining_requests = rate_limit['rate']['remaining']
    print(f"\n{Fore.YELLOW}[!] Remaining requests : {Fore.RED}{remaining_requests}{Fore.GREEN}/{rate_limit['rate']['limit']}")
    
    if remaining_requests == 0:
        pass
        
    elif remaining_requests > 0:
        general(uname, headers)
        repos(uname, headers)
    

def general(uname, headers):
    url = f"https://api.github.com/users/{uname}"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        user_data = response.json()
        
        if user_data['name'] == 'API rate limit exceeded':
            pass
        
        print(f"\n{Fore.YELLOW}[!] Github infos")
        print(f"[?] source : {url}")
        print(f"{Fore.GREEN}[+] Name       : {Fore.YELLOW}{user_data['name']}")
        print(f"{Fore.GREEN}[+] Company    : {Fore.YELLOW}{user_data['company']}")
        print(f"{Fore.GREEN}[+] Location   : {Fore.YELLOW}{user_data['location']}")
        print(f"{Fore.GREEN}[+] Email      : {Fore.YELLOW}{user_data['email']}")
        print(f"{Fore.GREEN}[+] Twitter    : {Fore.YELLOW}{user_data['twitter_username']}")
        print(f"{Fore.GREEN}[+] Bio        : {Fore.YELLOW}{user_data['bio']}")
        print(f"{Fore.GREEN}[+] Repos      : {Fore.YELLOW}{user_data['public_repos']}")
        print(f"{Fore.GREEN}[+] Avatar     : {Fore.YELLOW}{user_data['avatar_url']}")
    else:
        pass


def get_repositories(uname, headers):
    url = f"https://api.github.com/users/{uname}/repos"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()  
    else:
        return []


def get_commits(username, repo_name, headers):
    url = f"https://api.github.com/repos/{username}/{repo_name}/commits"
    response = requests.get(url, headers=headers)  
    if response.status_code == 200:
        return response.json()  
    else:
        return []


def extract_emails_from_commits(commits, repo_name):
    emails = []
    for commit in commits:
        try:
            email = commit['commit']['author']['email']
            
            # Vérification si 'author' existe et est un objet valide
            if commit.get('author') is not None:
                username = commit['author'].get('login', 'Unknown')  # Utilisation de .get() pour éviter les erreurs
            else:
                username = 'Unknown'
            
            if email not in [e['email'] for e in emails]:  # Vérification pour éviter les doublons
                emails.append({'email': email, 'username': username, 'repo': repo_name})
        except KeyError:
            continue
    return emails


def repos(uname, headers):
    repos = get_repositories(uname, headers)
    user_emails = {}  # Dictionnaire pour regrouper les résultats par username
    print("")
    
    for repo in repos:
        repo_name = repo['name']
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Extracting repo : {Fore.GREEN}{repo_name}")
        commits = get_commits(uname, repo_name, headers)
        emails = extract_emails_from_commits(commits, repo_name)
        
        # Regroupement des e-mails par username
        for email_info in emails:
            email = email_info['email']
            username = email_info['username']
            if username not in user_emails:
                user_emails[username] = []  # Créer une liste si l'utilisateur n'existe pas
            user_emails[username].append(f"{Fore.CYAN}{email} {Fore.GREEN}(Repo : {email_info['repo']})")
    
    print(f"\n{Fore.YELLOW}[!] Emails found grouped by username")
    print(f"[?] source : https://api.github.com/repos/{uname}/<REPO NAME>/commits")
    
    # Affichage des résultats par username
    for username, emails in user_emails.items():
        print(f"\n{Fore.GREEN}[+] User : {Fore.YELLOW}{username}")
        for email in emails:
            print(f"{Fore.GREEN}[+] {email}")
