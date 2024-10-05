import subprocess
import os
import sys
from colorama import init, Fore

# Init colorama
init()

# Variables
GHUNT_REPO = "https://github.com/mxrch/GHunt.git"
GHUNT_LOCAL_DIR = "Dependencies/ghunt"  

def update_repo(repo_url, local_dir, target):
    if os.path.exists(local_dir):
        initdirhunt(target)
    else:
        
        answer = input(f"{Fore.YELLOW}[?] GHunt is not installed. Do you want to install it? (y/n): {Fore.GREEN}").strip().lower()

        if answer == "y":
            print(f"{Fore.YELLOW}[!] Cloning repo {repo_url} to {local_dir}...{Fore.GREEN}")
            with open(os.devnull, 'wb') as hide_output:  
                subprocess.run(["git", "clone", repo_url, local_dir], stdout=hide_output, stderr=hide_output)

            print(f"{Fore.YELLOW}[!] Installing dependencies from requirements.txt...{Fore.GREEN}")
            requirements_path = os.path.join(local_dir, "requirements.txt")

            with open(os.devnull, 'wb') as hide_output:  
                subprocess.run(["pip", "install", "-r", requirements_path], stdout=hide_output, stderr=hide_output)

            print(f"{Fore.GREEN}[+] {Fore.YELLOW}GHunt and dependencies installed successfully !{Fore.GREEN}")
            print(f"{Fore.YELLOW}[!] Launching GHunt in a new window...{Fore.GREEN}")
            initdirhunt(target)
        else:
            print(f"{Fore.RED}[!] GHunt installation skipped.{Fore.GREEN}")

def initdirhunt(email):
    ghunt_script_path = os.path.join(GHUNT_LOCAL_DIR, "main.py")  
    if os.name == 'nt':  
        command = f'start cmd /k "python {ghunt_script_path} email {email}"'
    else:  
        command = f'gnome-terminal -- bash -c "python3 {ghunt_script_path} email {email}; exec bash"'

    os.system(command)

def ghunter(email):
    update_repo(GHUNT_REPO, GHUNT_LOCAL_DIR, email)

