import requests, json, os


from colorama import init, Fore, Style

init()  # Init colorama for colored text in terminal


def leakXx(ip):

    token_file_path = 'Tokens/leakix_token.txt'
    if os.path.exists(token_file_path):
        with open(token_file_path, 'r') as file:
            token_content = file.read().strip()
            if token_content:  
                token = token_content
            else:
                return

    
    encoded_query = requests.utils.quote(ip)

    url = f"https://leakix.net/search?scope=leak&page=0&q={encoded_query}"

    headers = {
        'api-key': token,
        'accept': 'application/json'
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        
        def print_json(data, indent=0):
            if isinstance(data, dict):
                for key, value in data.items():
                    print(' ' * indent + str(key) + ': ', end='')
                    if isinstance(value, (dict, list)):
                        print()  
                        print_json(value, indent + 4)  
                    else:
                        print(value)
            elif isinstance(data, list):
                for index, item in enumerate(data):
                    print(' ' * indent + f'Item {index}:')
                    print_json(item, indent + 4)  


        print(f"\n{Fore.YELLOW}[!] leakix datas on {Fore.GREEN}{ip}")
        print(f"{Fore.YELLOW}-------------------------------------{Fore.GREEN}")
        print_json(data)
        print(f"{Fore.YELLOW}-------------------------------------{Fore.GREEN}")
        
    else:
        pass

