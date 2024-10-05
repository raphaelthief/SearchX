import trio, importlib, pkgutil, httpx, os, subprocess
from colorama import init, Fore, Style

init() # Init colorama

try:
    from holehe.instruments import TrioProgress
    from termcolor import colored
except:
    None
  
  
def check_holehe(email):
    try:
        import holehe
        print(f"{Fore.YELLOW}Done. Launching holehe ...")
        holehez(email)
    except ImportError:
        print(f"{Fore.YELLOW}[!] holehe not found. Installing holehe ...{Fore.GREEN}")
        
        with open(os.devnull, 'wb') as hide_output:
            result = subprocess.run(["pip", "install", "holehe"], stdout=hide_output, stderr=hide_output)
        
        if result.returncode == 0:
            print(f"{Fore.YELLOW}Done. Launching holehe ...")
            holehez(email)
        else:
            print(f"{Fore.RED}Error: Failed to install holehe.")


def import_submodules(package, recursive=True):
    """Get all the holehe submodules"""
    if isinstance(package, str):
        package = importlib.import_module(package)
    results = {}
    for loader, name, is_pkg in pkgutil.walk_packages(package.__path__):
        full_name = package.__name__ + '.' + name
        results[full_name] = importlib.import_module(full_name)
        if recursive and is_pkg:
            results.update(import_submodules(full_name))
    return results


def get_functions(modules):
    """Transform the modules objects to functions"""
    websites = []

    for module in modules:
        if len(module.split(".")) > 3 :
            modu = modules[module]
            site = module.split(".")[-1]
         
            websites.append(modu.__dict__[site])
    return websites


def print_result(data,email,websites):
  
    def print_color(text,color):
        return(colored(text,color))
        
    description = print_color("[+] Email used","green") + "," + print_color(" [-] Email not used", "magenta") + "," + print_color(" [x] Rate limit","red")

    
    print("\n\n" + description + "\n")

    for results in data:
        if results["rateLimit"]:
            websiteprint = print_color("[x] " + results["domain"], "red")
            print(websiteprint)
        elif results["exists"] == False:
            websiteprint = print_color("[-] " + results["domain"], "magenta")
            print(websiteprint)
        elif results["exists"] == True:
            toprint = ""
            if results["emailrecovery"] is not None:
                toprint += " " + results["emailrecovery"]
            if results["phoneNumber"] is not None:
                toprint += " / " + results["phoneNumber"]
            if results["others"] is not None and "FullName" in str(results["others"].keys()):
                toprint += " / FullName " + results["others"]["FullName"]
            if results["others"] is not None and "Date, time of the creation" in str(results["others"].keys()):
                toprint += " / Date, time of the creation " + results["others"]["Date, time of the creation"]

            websiteprint = print_color("[+] " + results["domain"] + toprint, "green")
            print(websiteprint)
            
    print("")
 
 
async def launch_module(module,email, client, out):
    data={'aboutme': 'about.me', 'adobe': 'adobe.com', 'amazon': 'amazon.com', 'anydo': 'any.do', 'archive': 'archive.org', 'armurerieauxerre': 'armurerie-auxerre.com', 'atlassian': 'atlassian.com', 'babeshows': 'babeshows.co.uk', 'badeggsonline': 'badeggsonline.com', 'biosmods': 'bios-mods.com', 'biotechnologyforums': 'biotechnologyforums.com', 'bitmoji': 'bitmoji.com', 'blablacar': 'blablacar.com', 'blackworldforum': 'blackworldforum.com', 'blip': 'blip.fm', 'blitzortung': 'forum.blitzortung.org', 'bluegrassrivals': 'bluegrassrivals.com', 'bodybuilding': 'bodybuilding.com', 'buymeacoffee': 'buymeacoffee.com', 'cambridgemt': 'discussion.cambridge-mt.com', 'caringbridge': 'caringbridge.org', 'chinaphonearena': 'chinaphonearena.com', 'clashfarmer': 'clashfarmer.com', 'codecademy': 'codecademy.com', 'codeigniter': 'forum.codeigniter.com', 'codepen': 'codepen.io', 'coroflot': 'coroflot.com', 'cpaelites': 'cpaelites.com', 'cpahero': 'cpahero.com', 'cracked_to': 'cracked.to', 'crevado': 'crevado.com', 'deliveroo': 'deliveroo.com', 'demonforums': 'demonforums.net', 'devrant': 'devrant.com', 'diigo': 'diigo.com', 'discord': 'discord.com', 'docker': 'docker.com', 'dominosfr': 'dominos.fr', 'ebay': 'ebay.com', 'ello': 'ello.co', 'envato': 'envato.com', 'eventbrite': 'eventbrite.com', 'evernote': 'evernote.com', 'fanpop': 'fanpop.com', 'firefox': 'firefox.com', 'flickr': 'flickr.com', 'freelancer': 'freelancer.com', 'freiberg': 'drachenhort.user.stunet.tu-freiberg.de', 'garmin': 'garmin.com', 'github': 'github.com', 'google': 'google.com', 'gravatar': 'gravatar.com', 'imgur': 'imgur.com', 'instagram': 'instagram.com', 'issuu': 'issuu.com', 'koditv': 'forum.kodi.tv', 'komoot': 'komoot.com', 'laposte': 'laposte.fr', 'lastfm': 'last.fm', 'lastpass': 'lastpass.com', 'mail_ru': 'mail.ru', 'mybb': 'community.mybb.com', 'myspace': 'myspace.com', 'nattyornot': 'nattyornotforum.nattyornot.com', 'naturabuy': 'naturabuy.fr', 'ndemiccreations': 'forum.ndemiccreations.com', 'nextpvr': 'forums.nextpvr.com', 'nike': 'nike.com', 'odnoklassniki': 'ok.ru', 'office365': 'office365.com', 'onlinesequencer': 'onlinesequencer.net', 'parler': 'parler.com', 'patreon': 'patreon.com', 'pinterest': 'pinterest.com', 'plurk': 'plurk.com', 'pornhub': 'pornhub.com', 'protonmail': 'protonmail.ch', 'quora': 'quora.com', 'rambler': 'rambler.ru', 'redtube': 'redtube.com', 'replit': 'replit.com', 'rocketreach': 'rocketreach.co', 'samsung': 'samsung.com', 'seoclerks': 'seoclerks.com', 'sevencups': '7cups.com', 'smule': 'smule.com', 'snapchat': 'snapchat.com', 'soundcloud': 'soundcloud.com', 'sporcle': 'sporcle.com', 'spotify': 'spotify.com', 'strava': 'strava.com', 'taringa': 'taringa.net', 'teamtreehouse': 'teamtreehouse.com', 'tellonym': 'tellonym.me', 'thecardboard': 'thecardboard.org', 'therianguide': 'forums.therian-guide.com', 'thevapingforum': 'thevapingforum.com', 'tumblr': 'tumblr.com', 'tunefind': 'tunefind.com', 'twitter': 'twitter.com', 'venmo': 'venmo.com', 'vivino': 'vivino.com', 'voxmedia': 'voxmedia.com', 'vrbo': 'vrbo.com', 'vsco': 'vsco.co', 'wattpad': 'wattpad.com', 'wordpress': 'wordpress.com', 'xing': 'xing.com', 'xnxx': 'xnxx.com', 'xvideos': 'xvideos.com', 'yahoo': 'yahoo.com','hubspot': 'hubspot.com', 'pipedrive': 'pipedrive.com', 'insightly': 'insightly.com', 'nutshell': 'nutshell.com', 'zoho': 'zoho.com', 'axonaut': 'axonaut.com', 'amocrm': 'amocrm.com', 'nimble': 'nimble.com', 'nocrm': 'nocrm.io', 'teamleader': 'teamleader.eu'}
    try:
        await module(email, client, out)
    except Exception:
        name=str(module).split('<function ')[1].split(' ')[0]
        out.append({"name": name,"domain":data[name],
                    "rateLimit": True,
                    "exists": False,
                    "emailrecovery": None,
                    "phoneNumber": None,
                    "others": None})


async def maincore(v1):
    email= v1

    # Import Modules
    modules = import_submodules("holehe.modules")
    websites = get_functions(modules)
    # Get timeout
    timeout=10
   
    # Def the async client
    client = httpx.AsyncClient(timeout=timeout)
    # Launching the modules
    out = []
    instrument = TrioProgress(len(websites))
    trio.lowlevel.add_instrument(instrument)
    async with trio.open_nursery() as nursery:
        for website in websites:
            nursery.start_soon(launch_module, website, email, client, out)
    trio.lowlevel.remove_instrument(instrument)
    # Sort by modules names
    out = sorted(out, key=lambda i: i['name'])
    # Close the client
    await client.aclose()
    # Print the result
    print_result(out,email,websites)


def holehez(email):
    try:
        print(f"{Fore.YELLOW}\n[!] Searching for {Fore.GREEN}{email}\n")
        trio.run(maincore, email)
    except Exception as e:
        print(f"{Fore.RED}Error : {e}")

    
    