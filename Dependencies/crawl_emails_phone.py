import sys
import requests
import re

# colorama
from colorama import init, Fore, Style

init() # Init colorama

def extract_emails(html):
    """Extracts email addresses from an HTML page"""
    return set(re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', html))


def extract_french_phone_numbers(html):
    """Extracts all valid French phone numbers from an HTML page"""
    pattern = re.compile(r"""
        (?:\+33|0033)               # Country code for France (prefixes +33 or 0033)
        [\s.-]?                     
        (?:0?[1-9])                  
        (?:[\s.-]?\d{2}){4}         
        |
        0[1-9]                      
        (?:[\s.-]?\d{2}){4}         
        |
        \d{10}                      
    """, re.VERBOSE)

    found_numbers = re.findall(pattern, html)
    valid_numbers = [num for num in found_numbers if not re.match(r"^\d{8,}$", num)]
    valid_numbers = [num for num in valid_numbers if not re.search(r'[-.].*[-.]', num)]
    return set(valid_numbers)


def process_page(url):
    """Download and analyze a page to extract emails and phone numbers"""
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            html_content = response.text

            emails = extract_emails(html_content)
            for email in emails:
                print(f"{Fore.GREEN}[+] {Fore.YELLOW}Found email : {Fore.CYAN}{email}")

            phones = extract_french_phone_numbers(html_content)
            for phone in phones:
                print(f"{Fore.GREEN}[+] {Fore.YELLOW}Found phone number : {Fore.CYAN}{phone}")

            return emails, phones
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error processing {url} : {e}")
    return set(), set()


def get_emails_phones(target):
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    process_page(target)


