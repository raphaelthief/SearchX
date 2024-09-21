import asyncio, sys, os, subprocess
from Dependencies.modules_skype.search import search

# colorama
from colorama import init, Fore, Style

init() # Init colorama



# Credits to https://github.com/Totoro2205/SkypeSearch
def skype(target, token_location):
    try:
        if len(target.strip()) < 2:
            print(f'{Fore.RED}[!] Invalid text to search in Skype{Fore.GREEN}\n\n')
            return

        data = target.strip()

        with open(token_location, 'r') as f:
            token = f.read().strip()
            if token == '':
                print(f'{Fore.RED}[!] Insert your Skype access token in token.txt and re-run function{Fore.GREEN}\n\n')
                return
        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():  # If the event loop is closed, create a new one
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            loop.run_until_complete(search(data, token))    
        except Exception as e:
            print(f'{Fore.RED}[!] Error : {str(e)} {Fore.GREEN}\n\n') 
     
    except Exception as e:
        print(f'{Fore.RED}[!] Error : {str(e)} {Fore.GREEN}\n\n')
