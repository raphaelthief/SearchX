import time, json, requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# colorama
from colorama import init, Fore, Style

init() 

def cybernews(email):
    options = Options()
    driver = webdriver.Chrome(options=options)

    driver.get("https://cybernews.com/personal-data-leak-check/")
    time.sleep(4)  

    email = email
    script = f"""
    fetch("https://data-leak-check.cybernews.com/chk/email", {{
        method: "POST",
        headers: {{
            "Content-Type": "application/json"
        }},
        body: JSON.stringify({{"email": "{email}"}})
    }})
    .then(response => response.json())
    .then(data => window.result = data)
    .catch(error => window.result = {{error: error.toString()}});
    """
    driver.execute_script(script)

    time.sleep(2)
    result = driver.execute_script("return window.result;")
    driver.quit()

    if result and "dataLeakEmails" in result:
        total = result.get("total", 0)
        print(f"\n{Fore.YELLOW}[!] cybernews db")
        print(f"{Fore.YELLOW}[?] Source : https://cybernews.com/personal-data-leak-check/")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Total : {Fore.GREEN}{total}")
        for leak in result["dataLeakEmails"]:
            print(f" {Fore.YELLOW}--> {Fore.GREEN}{leak['name']})")
    elif "error" in result:
        pass
    else:
        pass


def cybernews1(phone):
    options = Options()
    driver = webdriver.Chrome(options=options)

    driver.get("https://cybernews.com/personal-data-leak-check/")
    time.sleep(2) 

    phone = phone
    script = f"""
    fetch("https://data-leak-check.cybernews.com/chk/phone", {{
        method: "POST",
        headers: {{
            "Content-Type": "application/json"
        }},
        body: JSON.stringify({{"phone": "{phone}"}})
    }})
    .then(response => response.json())
    .then(data => window.result = data)
    .catch(error => window.result = {{error: error.toString()}});
    """
    driver.execute_script(script)

    time.sleep(2)
    result = driver.execute_script("return window.result;")
    driver.quit()

    if result and "dataLeakPhones" in result:
        total = result.get("total", 0)
        print(f"\n{Fore.YELLOW}[!] cybernews db")
        print(f"{Fore.YELLOW}[?] Source : https://cybernews.com/personal-data-leak-check/")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Total : {Fore.GREEN}{total}")
        for leak in result["dataLeakPhones"]:
            print(f" {Fore.YELLOW}--> {Fore.GREEN}{leak['name']})")
    elif "error" in result:
        pass
    else:
        pass


def init_cybernews(target, what):
    if what == "email":
        cybernews(target)    
    elif what == "phone":    
        cybernews1(target)
