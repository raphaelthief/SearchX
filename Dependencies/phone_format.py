import phonenumbers
from phonenumbers import geocoder, carrier, timezone

from colorama import init, Fore, Style
init() # Init colorama

def basicinfos(phone):
    
    try:
        parse = phonenumbers.parse(phone)
        ValidNumber = phonenumbers.is_valid_number(parse)
        
        if ValidNumber is True:

            print(f"\n{Fore.YELLOW}[!] Phone format{Fore.GREEN}")
            print(f"{Fore.GREEN}[+] {phone}{Fore.YELLOW} is in valid format")
            region = geocoder.description_for_number(parse, 'fr')
            tiimezone = timezone.time_zones_for_number(parse)
            
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Format       : {Fore.GREEN}{parse}")
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Région       : {Fore.GREEN}{region}")
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Time Zone    : {Fore.GREEN}{tiimezone}")
            
            varrier = carrier.name_for_number(parse, 'fr')
            print(f"{Fore.GREEN}[+] {Fore.YELLOW}Fournisseur  : {Fore.GREEN}{varrier}")
            print("")
        else:
            print(f"{Fore.RED}{phone} is invalid\n")
            
    except:
        print(f"{Fore.RED}Error : {phone} is invalid (try format like +PHONECODE_PHONENUMBER ; use phone code with '+')\n")





    