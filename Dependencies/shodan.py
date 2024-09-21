import requests, re, json
from bs4 import BeautifulSoup

# colorama
from colorama import init, Fore, Style

init() # Init colorama


def shodanit(ip):
    url = f"https://www.shodan.io/host/{ip}"
    response = requests.get(url)
    headers = response.headers

    if "text/html" in headers.get("Content-Type", ""):
        soup = BeautifulSoup(response.content, 'html.parser')
        technologiesX = []
        
        try: ports_div = soup.find('div', {'id': 'ports'})
        except: ports_div = None
        try: general_info = soup.find('table', {'class': 'u-full-width'}).text 
        except: general_info = None

        if general_info:
            cleaned_general_info = "\n".join([line.strip() for line in general_info.splitlines() if line.strip()])
            print(f"{Fore.YELLOW}[!] General infos {Fore.GREEN}")
            print(cleaned_general_info)
            print("")
            
        try:
            print(f"{Fore.YELLOW}[!] Technologies {Fore.GREEN}")
            for category in soup.select('.category'):
                category_name = category.select_one('.category-heading').text.strip()
                tech_items = category.select('.technologies a')
                
                for item in tech_items:
                    tech_name = item.select_one('.technology-name').text.strip()
                    tech_version = item.select_one('.technology-version')
                    version = tech_version.text.strip() if tech_version else "N/A"
                    
                    technologiesX.append({
                        "category": category_name,
                        "name": tech_name,
                        "version": version
                    })
            
                for tech in technologiesX:
                    print(f"{Fore.GREEN}[+] {Fore.YELLOW}Category   : {Fore.GREEN}{tech['category']}")
                    print(f"{Fore.GREEN}[+] {Fore.YELLOW}Name       : {Fore.GREEN}{tech['name']}")
                    print(f"{Fore.GREEN}[+] {Fore.YELLOW}Version    : {Fore.GREEN}{tech['version']}")
                    print(f"{Fore.YELLOW}--------")
            print("")
        except:
            pass
            
        try:
            script = soup.find('script', text=re.compile(r'const VULNS'))
            if script:
                script_content = script.string

                vulns_json_match = re.search(r'const VULNS = ({.*?});', script_content, re.DOTALL)
                if vulns_json_match:
                    vulns_json = vulns_json_match.group(1)
                    vulnerabilities = json.loads(vulns_json)

                    print(f"{Fore.YELLOW}[!] Vulnerability {Fore.GREEN}")
                    for cve, details in vulnerabilities.items():
                        cvss = details['cvss']
                        ports = ", ".join(map(str, details['ports']))
                        summary = details['summary']
                        verified = "Yes" if details['verified'] else "No"
                        
                        print(f"{Fore.GREEN}[+] {Fore.YELLOW}CVE     : {Fore.GREEN}{cve}")
                        print(f"{Fore.GREEN}[+] {Fore.YELLOW}CVSS    : {Fore.GREEN}{cvss}")
                        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Ports   : {Fore.GREEN}{ports}")
                        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Checked : {Fore.GREEN}{verified}")
                        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Summary : {Fore.GREEN}{summary}\n")
                else:
                    pass
            else:
                pass
        except:
            pass

        if ports_div:
            ports = ports_div.find_all('a', {'class': 'bg-primary'})
            print(f"{Fore.YELLOW}[!] Open Ports")
            for port in ports:
                print(f"{Fore.GREEN}[+] {Fore.YELLOW}Port {Fore.GREEN}{port.text.strip()}")
            
            for port in ports:
                port_id = port['href'][1:]  
                port_details = soup.find('h6', {'id': port_id})
                
                if port_details:
                    protocol_info = port_details.find('span').text.strip()
                    protocol_info_cleaned = protocol_info.replace("\n", " ")

                    print(f"\n{Fore.YELLOW}[!] Details for port {Fore.GREEN}{port_id}")
                    print(f"{Fore.GREEN}[+] {Fore.YELLOW}Protocol : {Fore.GREEN}{protocol_info_cleaned}")
                    
                    banner = port_details.find_next('div', {'class': 'banner'})
                    if banner:
                        try : 
                            banner_title = banner.find('h1', {'class': 'banner-title'}).text.strip()
                            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Service : {Fore.GREEN}{banner_title}")
                        except:
                            pass
                            
                        try : 
                            http_info = banner.find('pre').text.strip()
                            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Info \n{Fore.GREEN}{http_info}")
                        except:
                            pass
                        
                        try :
                            if "SSL Certificate" in banner.text:
                                precertif = banner.find_next('pre')
                                ssl_info = precertif.find_next('pre').text.strip()
                                print(f"\n{Fore.GREEN}[+] {Fore.YELLOW}SSL Certificate Info \n{Fore.GREEN}{ssl_info}")
                        except:
                            pass
        else:
            pass
            