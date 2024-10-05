import requests
import json
import os

# colorama
from colorama import init, Fore, Style

init() # Init colorama


def get_vulnerabilities(api_url):
    response = requests.get(api_url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"{Fore.RED}API error: {response.status_code}")
        return None


def display_results(vulnerabilities):
    print(f"\n{Fore.YELLOW}--- Vulnerability list ---")
    for i, vulnerability in enumerate(vulnerabilities['vulnerabilities']):
        severity = "Unknow"
        try:
            severity = vulnerability['cve']['metrics']['cvssMetricV2'][0]['baseSeverity']
        except (KeyError, IndexError):
            severity = "Unknow"


        if severity == "HIGH":
            color = Fore.RED
        elif severity == "MEDIUM":
            color = Fore.CYAN
        elif severity == "LOW":
            color = Fore.GREEN
        else:  # "Unknown" or any other severity
            color = Fore.WHITE

        print(f"{Fore.GREEN}{i + 1}. {Fore.YELLOW}{vulnerability['cve']['id']} ({color}{severity}{Fore.YELLOW}) : {Fore.GREEN}{vulnerability['cve']['descriptions'][0]['value']}")


def save_results(data, filename='vulnerabilities.json'):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)


def load_results(filename='vulnerabilities.json'):
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return json.load(f)
    return None


def display_cve_details(cve_details):
    print(f"\n{Fore.CYAN}--- Détails du CVE sélectionné ---{Fore.GREEN}")
    

    print(f"{Fore.MAGENTA}ID :{Fore.GREEN} {cve_details['cve'].get('id', 'N/A')}")
    print(f"{Fore.MAGENTA}Source identifier :{Fore.GREEN} {cve_details['cve'].get('sourceIdentifier', 'N/A')}")
    print(f"{Fore.MAGENTA}Published :{Fore.GREEN} {cve_details['cve'].get('published', 'N/A')}")
    print(f"{Fore.MAGENTA}Last modified :{Fore.GREEN} {cve_details['cve'].get('lastModified', 'N/A')}")
    print(f"{Fore.MAGENTA}Vuln status :{Fore.GREEN} {cve_details['cve'].get('vulnStatus', 'N/A')}")
    print(f"{Fore.MAGENTA}CVE Tags :{Fore.GREEN} {cve_details['cve'].get('cveTags', 'N/A')}")
    

    descriptions = cve_details['cve'].get('descriptions', [])
    if descriptions:
        print(f"\n{Fore.YELLOW}Descriptions :{Fore.GREEN}")
        for desc in descriptions:
            lang = desc.get('lang', 'N/A')
            value = desc.get('value', 'No description available')
            print(f"  {Fore.YELLOW}- [{Fore.GREEN}{lang}{Fore.YELLOW}] :{Fore.GREEN} {value}")
    else:
        print(f"\n{Fore.YELLOW}No description available{Fore.GREEN}")
    

    metrics = cve_details['cve'].get('metrics', {})
    if metrics:
        print(f"\n{Fore.YELLOW}[!] CVSS metrics :{Fore.GREEN}")

        cvss_v2 = metrics.get('cvssMetricV2', [])
        if cvss_v2:
            print(f"{Fore.BLUE}CVSS v2 :{Fore.GREEN}")
            for metric in cvss_v2:
                cvss_data = metric.get('cvssData', {})
                print(f"  - Source : {metric.get('source', 'N/A')}")
                print(f"    Version CVSS : {cvss_data.get('version', 'N/A')}")
                print(f"    Vecteur d'accès : {cvss_data.get('vectorString', 'N/A')}")
                print(f"    Score de base : {cvss_data.get('baseScore', 'N/A')}")
                print(f"    Gravité : {metric.get('baseSeverity', 'N/A')}")
                print(f"    Score d'exploitabilité : {metric.get('exploitabilityScore', 'N/A')}")
                print(f"    Score d'impact : {metric.get('impactScore', 'N/A')}")
        else:
            print("")
        

        cvss_v3 = metrics.get('cvssMetricV3', [])
        if cvss_v3:
            print(f"\n{Fore.BLUE}CVSS v3 :{Fore.GREEN}")
            for metric in cvss_v3:
                cvss_data = metric.get('cvssData', {})
                print(f"  - Source : {metric.get('source', 'N/A')}")
                print(f"    CVSS Version : {cvss_data.get('version', 'N/A')}")
                print(f"    Access vector : {cvss_data.get('vectorString', 'N/A')}")
                print(f"    Base score : {cvss_data.get('baseScore', 'N/A')}")
                print(f"    Severity : {metric.get('baseSeverity', 'N/A')}")
                print(f"    Exploitability Score : {metric.get('exploitabilityScore', 'N/A')}")
                print(f"    Impact Score : {metric.get('impactScore', 'N/A')}")
        else:
            print("")
    else:
        print(f"\n{Fore.YELLOW}[!] No metrics aviable{Fore.GREEN}")
    

    weaknesses = cve_details['cve'].get('weaknesses', [])
    if weaknesses:
        print(f"\n{Fore.YELLOW}[!] Weakness (CWE) :{Fore.GREEN}")
        for weakness in weaknesses:
            descriptions = weakness.get('description', [])
            for desc in descriptions:
                lang = desc.get('lang', 'N/A')
                value = desc.get('value', 'N/A')
                print(f"  - {value} (lang: {lang})")
    else:
        print(f"\n{Fore.YELLOW}[!] No CWE aviable{Fore.GREEN}")
    

    configurations = cve_details['cve'].get('configurations', [])
    if configurations:
        print(f"\n{Fore.YELLOW}[!] Vulnerables configurations :{Fore.GREEN}")
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                operator = node.get('operator', 'N/A')
                print(f"  - Operator : {operator}")
                cpe_matches = node.get('cpeMatch', [])
                for match in cpe_matches:
                    vulnerable = match.get('vulnerable', False)
                    criteria = match.get('criteria', 'N/A')
                    version_end = match.get('versionEndIncluding', 'N/A')
                    print(f"    - Product : {criteria} (Vulnérable : {vulnerable})")
                    if version_end != 'N/A':
                        print(f"      Vulnerable version to : {version_end}")
    else:
        print(f"\n{Fore.YELLOW}[!] No configuration aviable{Fore.GREEN}")
    

    references = cve_details['cve'].get('references', [])
    if references:
        print(f"\n{Fore.YELLOW}[!] References :{Fore.GREEN}")
        for ref in references:
            url = ref.get('url', 'N/A')
            source = ref.get('source', 'N/A')
            tags = ref.get('tags', [])
            tags_str = ', '.join(tags) if tags else 'N/A'
            print(f"  {Fore.YELLOW}- URL : {Fore.GREEN}{url}")
            print(f"    {Fore.YELLOW}Source : {Fore.GREEN}{source}")
            print(f"    {Fore.YELLOW}Tags : {Fore.GREEN}{tags_str}")
            print(f"{Fore.YELLOW}-----")
    else:
        print(f"\n{Fore.YELLOW}[!] No reference aviable{Fore.GREEN}")
        
    print(f"{Fore.GREEN}")


def keywordcve(search_query):
    api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search_query}&keywordExactMatch"  
    
    while True:
        vulnerabilities = get_vulnerabilities(api_url)
        if vulnerabilities:

            display_results(vulnerabilities)
            choice = input("Select an ID for more details (or 'q' to exit) : ")
            if choice.lower() == 'q':
                break

            try:
                index = int(choice) - 1
                if 0 <= index < len(vulnerabilities['vulnerabilities']):
                    selected_vuln = vulnerabilities['vulnerabilities'][index]
                    display_cve_details(selected_vuln)  
                else:
                    print(f"{Fore.RED}Invalid selection")
            except ValueError:
                print(f"{Fore.RED}Enter a valid ID")

        else:
            print(f"{Fore.RED}No datas found")

        back = input("Press 'b' to go back to CVE list or 'q' to exit : ")
        if back.lower() == 'q':
            break




#keywordcve("iconv")  
        
        
# =============================== CVE ID ==================================
def search_cve_by_id(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"{Fore.RED}Error : {response.status_code}")
        return None


def print_cve_details(cve_id):
    try:
        result = search_cve_by_id(cve_id)

        if result:
            cna = result.get('containers', {}).get('cna', {})
            legacy = cna.get('x_legacyV4Record', {})
            cve_metadata = result.get('cveMetadata', {})

            print(f"{Fore.YELLOW}CVE ID         : {Fore.GREEN}{cve_metadata.get('cveId', 'N/A')}")
            print(f"{Fore.YELLOW}Assigner       : {Fore.GREEN}{cve_metadata.get('assignerShortName', 'N/A')}")
            print(f"{Fore.YELLOW}Date Published : {Fore.GREEN}{cve_metadata.get('datePublished', 'N/A')}")
            print(f"{Fore.YELLOW}Date Reserved  : {Fore.GREEN}{cve_metadata.get('dateReserved', 'N/A')}")
            print(f"{Fore.YELLOW}Date Updated   : {Fore.GREEN}{cve_metadata.get('dateUpdated', 'N/A')}")
            print(f"{Fore.YELLOW}State          : {Fore.GREEN}{cve_metadata.get('state', 'N/A')}")
            print("")

            descriptions = cna.get('descriptions', [])
            if descriptions:
                for description in descriptions:
                    print(f"{Fore.YELLOW}- Description :\n {Fore.GREEN}{description.get('value', 'N/A')}")
                    print("")
            else:
                print(f"{Fore.YELLOW}- Description : {Fore.GREEN}N/A")
                print("")

            problem_types = cna.get('problemTypes', [])
            if problem_types:
                for problem in problem_types:
                    descriptions = problem.get('descriptions', [])
                    for desc in descriptions:
                        print(f"{Fore.YELLOW}- Problem Type Description :\n {Fore.GREEN}{desc.get('description', 'N/A')} ({desc.get('lang', 'N/A')})")
                print("")
            else:
                print(f"{Fore.YELLOW}- Problem Types : {Fore.GREEN}N/A")
                print("")

            affected = cna.get('affected', [])
            if affected:
                for product in affected:
                    print(f"{Fore.YELLOW}Product          : {Fore.GREEN}{product.get('product', 'N/A')}")
                    print(f"{Fore.YELLOW}Vendor           : {Fore.GREEN}{product.get('vendor', 'N/A')}")
                    versions = product.get('versions', [])
                    if versions:
                        for version in versions:
                            lessthan = version.get('lessThan')
                            if lessthan:
                                print(f"{Fore.YELLOW}Affected version : {Fore.GREEN}{version.get('version', 'N/A')} < {version.get('lessThan')}")
                            else:    
                                print(f"{Fore.YELLOW}Affected version : {Fore.GREEN}{version.get('lessThan', 'N/A')}")
                            print(f"{Fore.YELLOW}Status           : {Fore.GREEN}{version.get('status', 'N/A')}")
                    print("")
            else:
                print(f"{Fore.YELLOW}Affected Products : {Fore.GREEN}N/A")
                print("")

            metrics = cna.get('metrics', [])
            if metrics:
                for metric in metrics:
                    cvss = metric.get('cvssV3_1') or metric.get('cvssV3_0') or metric.get('cvssV2_0')
                    if cvss:
                        print(f"{Fore.YELLOW}CVSS Version   : {Fore.GREEN}{cvss.get('version', 'N/A')}")
                        print(f"{Fore.YELLOW}Base Score     : {Fore.GREEN}{cvss.get('baseScore', 'N/A')}")
                        print(f"{Fore.YELLOW}Severity       : {Fore.GREEN}{cvss.get('baseSeverity', 'N/A')}")
                        print(f"{Fore.YELLOW}Vector String  : {Fore.GREEN}{cvss.get('vectorString', 'N/A')}")
                print("")
            else:
                print(f"{Fore.YELLOW}Security Metrics : {Fore.GREEN}N/A")
                print("")
            
            references = cna.get('references', [])
            if references:
                for reference in references:
                    print(f"{Fore.YELLOW}- Reference Name : {Fore.GREEN}{reference.get('name', 'N/A')}")
                    print(f"{Fore.YELLOW}             URL : {Fore.GREEN}{reference.get('url', 'N/A')}")
                    tags = reference.get('tags', [])
                    if tags:
                        print(f"{Fore.YELLOW}            Tags : {Fore.GREEN}{', '.join(tags)}")
                print("")
            else:
                print(f"{Fore.YELLOW}References : {Fore.GREEN}N/A")
                print("")

            provider_metadata = cna.get('providerMetadata', {})
            if provider_metadata:
                print(f"{Fore.YELLOW}Provider Metadata Org ID       : {Fore.GREEN}{provider_metadata.get('orgId', 'N/A')}")
                print(f"{Fore.YELLOW}Provider Metadata Short Name   : {Fore.GREEN}{provider_metadata.get('shortName', 'N/A')}")
                print(f"{Fore.YELLOW}Provider Metadata Date Updated : {Fore.GREEN}{provider_metadata.get('dateUpdated', 'N/A')}")
                print("")
            else:
                print(f"{Fore.YELLOW}Provider Metadata : {Fore.GREEN}N/A")
                print("")

            if legacy:
                print(f"{Fore.YELLOW}Legacy CVE ID : {Fore.GREEN}{legacy.get('CVE_data_meta', {}).get('ID', 'N/A')}")
                description_data = legacy.get('description', {}).get('description_data', [])
                if description_data:
                    for desc in description_data:
                        print(f"{Fore.YELLOW}Legacy Description :\n {Fore.GREEN}{desc.get('value', 'N/A')}")
                        print("")
                else:
                    print(f"{Fore.YELLOW}Legacy Description : {Fore.GREEN}N/A")
                    print("")
                
                references_data = legacy.get('references', {}).get('reference_data', [])
                if references_data:
                    for ref in references_data:
                        print(f"{Fore.YELLOW}Legacy Reference   : {Fore.GREEN}{ref.get('name', 'N/A')}")
                        print(f"{Fore.YELLOW}Legacy URL         : {Fore.GREEN}{ref.get('url', 'N/A')}")
                    print("")
                else:
                    print(f"{Fore.YELLOW}Legacy References : {Fore.GREEN}N/A")
                    print("")
                
            print(f"{Fore.YELLOW}[!] Source : {Fore.GREEN}https://www.cve.org/CVERecord?id={cve_id}")
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {e}")


#print_cve_details("CVE-2024-32002")



def searchcve(search_term=None, cve=None):
    if search_term:
        keywordcve(search_term)
        
    if cve:
        print_cve_details(cve)
