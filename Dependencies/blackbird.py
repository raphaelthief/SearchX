# Credits to https://github.com/p1ngul1n0/blackbird

import subprocess
import os
import sys
from colorama import init, Fore

# Init colorama
init()

# Variables
BLACKBIRD_REPO = "https://github.com/p1ngul1n0/blackbird.git"
BLACKBIRD_LOCAL_DIR = "Dependencies/blackbird"  



def update_repo(repo_url, local_dir, target, what):
    if os.path.exists(local_dir):
        if what == "email":
            emailhunt(target)
        elif what == "username":
            unamehunt(target)
            
    else:
        answer = input(f"{Fore.YELLOW}[?] Blackbird is not installed. Do you want to install it? (y/n): {Fore.GREEN}").strip().lower()

        if answer == "y":
            print(f"{Fore.YELLOW}[!] Cloning repo {repo_url} to {local_dir}...{Fore.GREEN}")
            with open(os.devnull, 'wb') as hide_output:  
                subprocess.run(["git", "clone", repo_url, local_dir], stdout=hide_output, stderr=hide_output)

            print(f"{Fore.YELLOW}[!] Installing dependencies from requirements.txt...{Fore.GREEN}")
            requirements_path = os.path.join(local_dir, "requirements.txt")

            with open(os.devnull, 'wb') as hide_output:  
                subprocess.run(["pip", "install", "-r", requirements_path], stdout=hide_output, stderr=hide_output)

            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Blackbird and dependencies installed successfully !{Fore.GREEN}")
            print(f"{Fore.YELLOW}[!] Launching Blackbird in a new window...{Fore.GREEN}")
            
            if what == "email":
                emailhunt(target)
            elif what == "username":
                unamehunt(target)
                
        else:
            print(f"{Fore.RED}[!] Blackbird installation skipped.{Fore.GREEN}")

def emailhunt(email):
    blackbird_script_path = os.path.join(BLACKBIRD_LOCAL_DIR, "blackbird.py")  
    if os.name == 'nt':  
        command = f'start cmd /k "cd {BLACKBIRD_LOCAL_DIR} && python blackbird.py --email {email}"'

    else:  
        command = f'gnome-terminal -- bash -c "cd {BLACKBIRD_LOCAL_DIR} && python3 blackbird.py --email {email}; exec bash"'

    os.system(command)

def unamehunt(username):
    blackbird_script_path = os.path.join(BLACKBIRD_LOCAL_DIR, "blackbird.py")  
    if os.name == 'nt':  
        command = f'start cmd /k "cd {BLACKBIRD_LOCAL_DIR} && python blackbird.py --username {username}"'

    else:  
        command = f'gnome-terminal -- bash -c "cd {BLACKBIRD_LOCAL_DIR} && python3 blackbird.py --username {username}; exec bash"'


    os.system(command)


def blackbirdhunt(target, what):
    update_repo(BLACKBIRD_REPO, BLACKBIRD_LOCAL_DIR, target, what)
