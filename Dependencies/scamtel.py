import cloudscraper
from bs4 import BeautifulSoup

# colorama
from colorama import init, Fore, Style

init() # Init colorama

def getscamtel(phone):
    print(f"\n{Fore.YELLOW}[!] scamtel rate")
    url_get_cookies = "https://fr.scamtel.com/"
    url_post = "https://fr.scamtel.com/interrogation"

    # Init Cloudscraper
    scraper = cloudscraper.create_scraper()

    # 1. Get cookies & CSRF
    response = scraper.get(url_get_cookies)
    if not response.status_code == 200:
        print(f"{Fore.RED}Request error : {response.status_code}")
        return

    # Extract CSRF token
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token_element = soup.find("input", {"name": "_csrf-frontend"})

    if not csrf_token_element:
        print(f"{Fore.RED}Error : CSRF token not found")
        return

    csrf_token = csrf_token_element.get("value")
    
    # 2. Load POST request
    payload = {
        "_csrf-frontend": csrf_token,
        "phone_number": phone
    }

    # Fake headers
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": url_get_cookies
    }

    # 3. Send POST request with cookies without redirections
    response_post = scraper.post(url_post, headers=headers, data=payload, allow_redirects=False)

    # Check status (statut code 3xx)
    location_url = response_post.headers.get('Location')

    response_get_redirect = scraper.get(location_url)

    # Check if succeed
    if response_get_redirect.status_code == 200:
        soup = BeautifulSoup(response_get_redirect.text, 'html.parser')
        
        # Found div
        report_details = soup.find('div', class_='report-other-details')
        
        print(f"{Fore.YELLOW}[!] Source : {Fore.GREEN}{location_url}") # Source
        if report_details:
            # Display infos from div
            title_info = report_details.find('h2', class_='h2-view')
            analysis_date = report_details.find('div', class_='analysis-date')
            table_rows = report_details.find_all('tr')

            # Display infos
            if analysis_date:
                print(f"{Fore.GREEN}[+]{Fore.YELLOW}", analysis_date.get_text(strip=True))  # Analysis date
            
            for row in table_rows:
                
                if row.get("id") == "phone_reviews":
                    continue  # Pass this one
                    
                columns = row.find_all('td')
                if len(columns) > 1:
                    label = columns[0].get_text(strip=True)
                    value = columns[1].get_text(strip=True)
                    print(f"{Fore.YELLOW}   - {label} : {Fore.GREEN}{value}")


        # Global score reputation
        slider_value = soup.find('input', id='final_score')
        if slider_value:
            print(f"\n{Fore.GREEN}[+] {Fore.YELLOW}Trusted score : {Fore.RED}{slider_value.get('value')}%")
        else:
            print(f"{Fore.RED}[-] Final Score input not found")


        interrogation_section = soup.find('div', class_='row align-items-start interrogation-points')
        if interrogation_section:
            columns = interrogation_section.find_all('div', class_=['col-md-6', 'interrogation-div'])

            for column in columns:
                title_element = column.find('p', class_='m-0')
                if title_element:
                    title = title_element.get_text(strip=True)
                    print(f"\n{Fore.GREEN}[+] {Fore.YELLOW}{title}")

                points = column.find_all('li')
                for idx, point in enumerate(points, start=1):
                    point_text = point.find('p')
                    if point_text:
                        print(f"{Fore.CYAN}   {idx}) {point_text.get_text(strip=True)}")
        else:
            print(f"{Fore.RED}[-] La section 'interrogation-points' est introuvable.")


    else:
        print(f"{Fore.RED}Request error : {response_get_redirect.status_code}")
        return
