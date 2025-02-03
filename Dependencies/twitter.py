import requests, sys, json

# colorama
from colorama import init, Fore, Style

init() # Init colorama


def fetch_web_archive_timemap(username: str):
    url = f"http://web.archive.org/web/timemap/?url=https://twitter.com/{username}&matchType=prefix&collapse=urlkey&output=json&fl=original,mimetype,timestamp"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        sys.stderr.write(f"Error fetching data: {e}\n")
        return None


def process_timemap(data):
    if not data:
        print("No data fetched.")
        return

    # Assuming the first element is header in the JSON output, skip it
    if isinstance(data, list):
        data = data[1:]

    for entry in data:
        if len(entry) >= 3:
            original_url = entry[0]
            web_archive_link = f"https://web.archive.org/web/0/{original_url}"
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Wayback  : {Fore.GREEN}{web_archive_link}")
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Original : {Fore.GREEN}{original_url}")
            print(f"{Fore.YELLOW}-------------")


def tweetwho(username):
    timemap_data = fetch_web_archive_timemap(username)
    process_timemap(timemap_data)
