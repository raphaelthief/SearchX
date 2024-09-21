import trio, importlib, pkgutil, httpx, os, subprocess
from colorama import init, Fore, Style
from termcolor import colored
init() # Init colorama

try:
    from ignorant.localuseragent import ua
    from ignorant.instruments import TrioProgress
    
    from ignorant.core import *
    from ignorant.localuseragent import *

except:
    None

code = None
new = None


def check_ignorant(phone):
    if os.path.isdir("ignorant"):
        print(f"{Fore.YELLOW}Done. Launching ignorant ...")
        code, new = separator(phone)
        
        if not code:
            print(f"{Fore.RED}Error: Invalid phone number format. Please include the country code (e.g., +1 for USA) {Fore.GREEN}")
            return
            
        goignorant(code, new)
        
    else:
        print(f"{Fore.YELLOW}[!] Downloading depedencies (ignorant) ...{Fore.GREEN}")
        command = ['git', 'clone', 'https://github.com/megadose/ignorant.git']
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"{Fore.YELLOW}Done. Launching ignorant ...")
            code, new = separator(phone)
            
            if not code:
                print(f"{Fore.RED}Error: Invalid phone number format. Please include the country code (e.g., +1 for USA) {Fore.GREEN}")
                return
            
            goignorant(code, new)
        else:
            print(f"{Fore.RED}Error : {result.stderr}")


def separator(phone):
    if phone.startswith('+'):
        code = phone[1:3]#phone[:3]
        new = phone[3:]
    else:
        code = None
        new = phone
    return code, new


def import_submodules2(package, recursive=True):
    """Get all the ignorant submodules"""
    if isinstance(package, str):
        package = importlib.import_module(package)
    results = {}
    for loader, name, is_pkg in pkgutil.walk_packages(package.__path__):
        full_name = package.__name__ + '.' + name
        results[full_name] = importlib.import_module(full_name)
        if recursive and is_pkg:
            results.update(import_submodules2(full_name))
    return results

def get_functions2(modules):
    """Transform the modules objects to functions"""
    websites = []

    for module in modules:
        if len(module.split(".")) > 3 :
            modu = modules[module]
            site = module.split(".")[-1]
            websites.append(modu.__dict__[site])
    return websites
    
    
def print_color(text,color):
    return(colored(text,color))


def print_result2(data,phone, country_code, websites):
    description = print_color("[+] Phone number used","green") + "," + print_color(" [-] Phone number not used", "magenta") + "," + print_color(" [x] Rate limit","red")
    print("\n\n" + description + "\n") 

    full_number="+"+str(country_code)+" "+str(phone)

   
    print("\n")
    print("*" * (len(full_number) + 6))
    print("   " + full_number)
    print("*" * (len(full_number) + 6))

    for results in data:
        if results["rateLimit"]:
            websiteprint = print_color("[x] " + results["domain"], "red")
            print(websiteprint)
        elif results["exists"] == False:
            websiteprint = print_color("[-] " + results["domain"], "magenta")
            print(websiteprint)
        elif results["exists"] == True:
            toprint = ""
            websiteprint = print_color("[+] " + results["domain"] + toprint, "green")
            print(websiteprint)
    print("")



async def launch_module2(module, phone, country_code, client, out):
    data={'amazon':'amazon.com','instagram':'instagram.com','snapchat': 'snapchat.com'}
    try:
        await module(phone, country_code, client, out)
    except :
        name=str(module).split('<function ')[1].split(' ')[0]
        out.append({"name": name,"domain":data[name],
                    "rateLimit": True,
                    "exists": False})

async def ignorantz(V2, Ccode):

    country_code= Ccode
    phone= V2

    # Import Modules
    modules = import_submodules2("ignorant.modules")
    websites = get_functions2(modules)

    timeout=10

    # Def the async client
    client = httpx.AsyncClient(timeout=timeout)
    # Launching the modules
    out = []
    instrument = TrioProgress(len(websites))
    trio.lowlevel.add_instrument(instrument)
    async with trio.open_nursery() as nursery:
        for website in websites:
            nursery.start_soon(launch_module2, website, phone, country_code, client, out)
    trio.lowlevel.remove_instrument(instrument)
    # Sort by modules names
    out = sorted(out, key=lambda i: i['name'])
    # Close the client
    await client.aclose()
    # Print the result
    print_result2(out,phone, country_code, websites)

    
def goignorant(countrycode, V2X):
    trio.run(ignorantz, V2X, countrycode)






