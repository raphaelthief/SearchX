# Credits to : https://github.com/Viralmaniar/Passhunt/blob/master/passhunt.py
# Part of the code taken from Viral Maniar 

import requests, urllib, csv
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


    ################################
    print(f"\n\n{Fore.YELLOW}[!] Searching default password for [{Fore.GREEN}{vendor}{Fore.YELLOW}] (https://many-passwords.github.io/)")
    defaultpass_wifi(vendor) # Go for IOT default passwords


def defaultpass_wifi(vendor):
    url = "https://raw.githubusercontent.com/many-passwords/many-passwords/main/passwords.csv"
    response = requests.get(url)
    found_match = False
    
    if response.status_code == 200:
        content = response.text.splitlines()

        reader = csv.reader(content)
        next(reader)  

        for row in reader:
            title = row[0]  
            model = row[1]  
            version = row[2]  
            access_type = row[3]  
            username = row[4]  
            password = row[5]  
            privileges = row[6]  

            if title == vendor:
                found_match = True
                print("")
                print(f"{Fore.GREEN}[+] {Fore.CYAN}{title}\n{Fore.YELLOW}------------------")
                print(f"{Fore.GREEN}Model       : {Fore.YELLOW}{model}")
                print(f"{Fore.GREEN}Version     : {Fore.YELLOW}{version}")
                print(f"{Fore.GREEN}Access type : {Fore.YELLOW}{access_type}")
                print(f"{Fore.GREEN}Username    : {Fore.RED}{username}")
                print(f"{Fore.GREEN}Password    : {Fore.RED}{password}")
                print(f"{Fore.GREEN}Privileges  : {Fore.YELLOW}{privileges}") 
                                
    else:
        print(f"{Fore.RED}[-] Error : {response.status_code}")

    if not found_match:
        print(f"{Fore.YELLOW}------------------\n{Fore.RED}[-] {Fore.GREEN}Nothing found for vendor : {Fore.RED}{vendor}\n{Fore.YELLOW}------------------{Fore.GREEN}")
