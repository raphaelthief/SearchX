import requests, json

# colorama
from colorama import init, Fore, Style

init() # Init colorama


def check_ip_with_virustotal(ip, api_key):
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

        with open(api_key, 'r') as f:
            token = f.read().strip()
            if token == '':
                pass
            
        headers = {
            "accept": "application/json",
            "x-apikey": token
        }
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            attributes = data['data']['attributes']
            
            # Safely access 'last_analysis_date' and other fields using get()
            last_analysis_date = attributes.get('last_analysis_date', 'Not available')
            country = attributes.get('country', 'Not available')
            regional_internet_registry = attributes.get('regional_internet_registry', 'Not available')
            whois_info = attributes.get('whois', 'Not available')

            print(f"{Fore.YELLOW}[!] Attributes")
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}IP Address : {Fore.GREEN}{data['data']['id']}")
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Country : {Fore.GREEN}{country}")
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Last analysis date : {Fore.GREEN}{last_analysis_date}")
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Regional internet registry : {Fore.GREEN}{regional_internet_registry}")
            print("")

            total_votes = attributes.get('total_votes', 'Not available')
            last_analysis_stats = attributes.get('last_analysis_stats', 'Not available')

            print(f"{Fore.YELLOW}[!] Total Votes : {Fore.GREEN}{total_votes}")
            print(f"{Fore.YELLOW}[!] Last Analysis Stats : {Fore.GREEN}{last_analysis_stats}")
            print(f"\n{Fore.YELLOW}[!] WHOIS Info :\n{Fore.GREEN}{whois_info}")
            print(f"{Fore.YELLOW}[!] Last Analysis Results")
            
            status_colors = {
                "clean": Fore.GREEN,
                "suspicious": Fore.RED,
                "malicious": Fore.RED,
                "malware": Fore.RED,
                "unrated": Fore.WHITE  
            }        
            
            for engine, result in attributes.get('last_analysis_results', {}).items():
                engine_length = max(len(e) for e in attributes['last_analysis_results'].keys())
                status_color = status_colors.get(result['result'], Fore.WHITE)
                print(f"{Fore.GREEN}[+] {Fore.YELLOW}{engine:<{engine_length}} : {status_color}{result['result']} {Fore.GREEN}({Fore.YELLOW}Category : {Fore.GREEN}{result['category']} | {Fore.YELLOW}Method : {Fore.GREEN}{result['method']})")
            
        else:
            pass
    except Exception as e:
        pass

