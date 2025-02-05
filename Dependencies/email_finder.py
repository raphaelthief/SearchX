import requests, json

# colorama
from colorama import init, Fore, Style

init() # Init colorama

def find_emails(first_name, last_name, domain):
    
    url = f"https://api.experte.com/tools/email-finder?name={first_name}%20{last_name}&domain={domain}"
    
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raises an exception for HTTP errors

        emails = response.json()

        if not emails:
            print("No emails found.")
            return

        print("\n=== Email Search Results ===")
        for idx, email_info in enumerate(emails, start=1):
            status_color = Fore.YELLOW if email_info['status'] == "valid" else Fore.RED
            stats = f"{Fore.GREEN}[+] " if email_info['status'] == "valid" else f"{Fore.RED}[-] "
            
            print(f"\n{stats}{Fore.YELLOW}Email {idx} : {Fore.CYAN}{email_info['email']}{Fore.GREEN}")
            print(f"      - Status            : {status_color}{email_info['status']}{Fore.GREEN}")
            print(f"      - Format Valid      : {'Yes' if email_info['format_valid'] else 'No'}")
            print(f"      - MX Found          : {'Yes' if email_info['mx_found'] else 'No'}")
            print(f"      - Server Connection : {'Yes' if email_info['server_connection'] else 'No'}")
            print(f"      - Server Response   : {'Yes' if email_info['server_response'] else 'No'}")
            print(f"      - Valid User        : {'Yes' if email_info['valid_user'] else 'No'}")
            print(f"      - Catch-All Address : {'Yes' if email_info['catch_all'] else 'No'}")
            message = email_info['message']
            if message:
                print(f"      - Message : {message}")

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}Request error : {e}")


