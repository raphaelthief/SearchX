import subprocess
import sys
import importlib.util
import platform
from colorama import init, Fore

init()

def ensure_maigret():
    if importlib.util.find_spec("maigret") is None:
        print(f"{Fore.YELLOW}[!] Installing maigret ...{Fore.GREEN}")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "-q", "maigret"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    else:
        pass

def run_maigret(username):
    ensure_maigret()
    system = platform.system()
    cmd = f"{sys.executable} -m maigret -a {username}"
    if system == "Windows":
        subprocess.Popen(["cmd", "/c", "start", "cmd", "/k", cmd])
    elif system == "Linux":
        subprocess.Popen(["x-terminal-emulator", "-e", f"bash -c '{cmd}; exec bash'"])
