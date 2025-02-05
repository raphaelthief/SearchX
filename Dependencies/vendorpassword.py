# Credits to : https://github.com/Viralmaniar/Passhunt/blob/master/passhunt.py
# Part of the code taken from Viral Maniar 

import requests, urllib
import bs4 as bs
from bs4 import BeautifulSoup

# colorama
from colorama import init, Fore, Style

init() # Init colorama


def formatTable(table):
    text = ''
    rows = table.find_all('tr')
    text += f'{Fore.RED}%s\n' % rows[0].text # Modif here (more beautiful form me)

    for row in rows[1:]:
        data = row.find_all('td')
        text += f'{Fore.GREEN}%s : {Fore.CYAN}%s\n' % (data[0].text, data[1].text) # Modif here (more beautiful form me)
        
    return text

def defaultpass(vendor):
    urlenc = urllib.parse.quote(vendor)
    url = "https://cirt.net/passwords?vendor=" + urlenc
    request = urllib.request.Request(url)
    response = urllib.request.urlopen(request)
    soup = bs.BeautifulSoup(response, "html.parser")
    
    tables = soup.find_all('table')
    
    if not tables:  # Modif here (more beautiful form me)
        print(f"{Fore.RED}[-] {Fore.GREEN}Nothing found for vendor : {Fore.RED}{vendor}\n{Fore.YELLOW}------------------{Fore.GREEN}") # Modif here (more beautiful form me)
    else:
        for table in tables:  # Modif here (more beautiful form me)
            print(formatTable(table) + f"{Fore.YELLOW}------------------{Fore.GREEN}")
