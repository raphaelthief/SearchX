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
    print(f"\n{Fore.YELLOW}[!] Remaining requests : {Fore.RED}{remaining_requests} {Fore.YELLOW}of {Fore.GREEN}{rate_limit['rate']['limit']}")
    
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
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Name       : {Fore.GREEN}{user_data['name']}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Company    : {Fore.GREEN}{user_data['company']}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Location   : {Fore.GREEN}{user_data['location']}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Email      : {Fore.GREEN}{user_data['email']}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Twitter    : {Fore.GREEN}{user_data['twitter_username']}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Bio        : {Fore.GREEN}{user_data['bio']}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Repos      : {Fore.GREEN}{user_data['public_repos']}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Avatar     : {Fore.GREEN}{user_data['avatar_url']}")
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


def extract_emails_from_commits(commits):
    emails = []
    for commit in commits:
        try:
            email = commit['commit']['author']['email']
            if email not in emails:  
                emails.append(email)
        except KeyError:
            continue
    return emails


def repos(uname, headers):
    repos = get_repositories(uname, headers)
    all_emails = set()
    print("")
    
    for repo in repos:
        repo_name = repo['name']
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Extracting repo : {Fore.GREEN}{repo_name}")
        commits = get_commits(uname, repo_name, headers)
        emails = extract_emails_from_commits(commits)
        all_emails.update(emails)
        
    print(f"\n{Fore.YELLOW}[!] Emails found")
    print(f"[?] source : https://api.github.com/repos/{uname}/<REPO NAME>/commits")
    
    for email in all_emails:
        print(f"{Fore.GREEN}[+] " + email)
