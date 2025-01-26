import subprocess, os, sys
from colorama import init, Fore

# Init colorama
init()

# Variables
GitFive_REPO = "https://github.com/mxrch/GitFive.git"
GitFive_LOCAL_DIR = "Dependencies/GitFive"  

def update_repo(repo_url, local_dir, target, what):
    if os.path.exists(local_dir):
        if what == "email":
            gitfive_email_full(target)
        else:
            gitfive_username_full(target)
    else:
        
        answer = input(f"{Fore.YELLOW}[?] GitFive is not installed. Do you want to install it? (y/n): {Fore.GREEN}").strip().lower()

        if answer == "y":
            print(f"{Fore.YELLOW}[!] Cloning repo {repo_url} to {local_dir}...{Fore.GREEN}")
            with open(os.devnull, 'wb') as hide_output:  
                subprocess.run(["git", "clone", repo_url, local_dir], stdout=hide_output, stderr=hide_output)

            print(f"{Fore.YELLOW}[!] Installing dependencies from requirements.txt...{Fore.GREEN}")
            requirements_path = os.path.join(local_dir, "requirements.txt")

            with open(os.devnull, 'wb') as hide_output:  
                subprocess.run(["pip", "install", "-r", requirements_path], stdout=hide_output, stderr=hide_output)

            print(f"{Fore.GREEN}[+] {Fore.YELLOW}GitFive and dependencies installed successfully !{Fore.GREEN}")
            print(f"{Fore.YELLOW}[!] Launching GitFive in a new window...{Fore.GREEN}")
            if what == "email":
                gitfive_email_full(target)
            else:
                gitfive_username_full(target)
                     
        else:
            print(f"{Fore.RED}[!] GitFive installation skipped.{Fore.GREEN}")


def gitfive_(target, what):
    update_repo(GitFive_REPO, GitFive_LOCAL_DIR, target, what)
    
    
# run email full
def gitfive_email_full(email):
    GitFive_script_path = os.path.join(GitFive_LOCAL_DIR, "main.py")  
    if os.name == 'nt':  
        command = f'start cmd /k "python {GitFive_script_path} email {email}"'
    else:  
        command = f'gnome-terminal -- bash -c "python3 {GitFive_script_path} email {email}; exec bash"'

    os.system(command)


# run username full
def gitfive_username_full(username):

    GitFive_script_path = os.path.join(GitFive_LOCAL_DIR, "main.py")  
    if os.name == 'nt':  
        command = f'start cmd /k "python {GitFive_script_path} user {username}"'
    else:  
        command = f'gnome-terminal -- bash -c "python3 {GitFive_script_path} user {username}; exec bash"'

    os.system(command)

