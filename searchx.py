# Of course, you're not going to use this tool to sift through ransomware leaks or any other crap. Don't be stupid and respect the law !

import os
import re
import argparse
from colorama import init, Fore, Back, Style

# Init colorama


init() # Init colorama

banner = (
    f"\n"
    f"                      {Fore.RED}#\n"                 
    f"                 {Fore.GREEN}%%%%%{Fore.RED}*{Fore.GREEN}%%%%%%                                                {Fore.YELLOW}Coded by {Fore.RED}raphaelthief\n"                 
    f"            {Fore.GREEN}%%%%%%%%%%{Fore.RED}#{Fore.GREEN}%%%%%%%%%%%                                                  {Fore.YELLOW}Colt45 Product\n"                 
    f"         {Fore.GREEN}%%%%%%%/     {Fore.RED}#      {Fore.GREEN}%%%%%%%%\n"                 
    f"       {Fore.GREEN}&%%%%%   {Fore.RED}(############(   {Fore.GREEN}%%%%%%\n"                 
    f"      {Fore.GREEN}%%%%%  {Fore.RED}*####    #     (###.  {Fore.GREEN}%%%%%\n"                 
    f"     {Fore.GREEN}%%%%%  {Fore.RED}###       #        ###  {Fore.GREEN}%%%%%\n"                 
    f"     {Fore.GREEN}%%%%  {Fore.RED}###                  ###  {Fore.GREEN}%%%%\n"                 
    f"  {Fore.RED}#*##############          ##############*#\n"                 
    f"    {Fore.GREEN}(%%%%                       {Fore.RED}###                                                {Fore.GREEN}###\n"                 
    f"     {Fore.GREEN}%%%%*                     {Fore.RED}###                                                  {Fore.GREEN}##\n"                
    f"      {Fore.GREEN}%%%%%           {Fore.RED}#      ####      {Fore.GREEN}#####    ####     ####    ######    ####     ##      {Fore.RED}##  ##\n"                 
    f"       {Fore.GREEN}&%%%%*         {Fore.RED}########,       {Fore.GREEN}##       ##  ##       ##    ##  ##  ##  ##    #####    {Fore.RED}####\n"                 
    f"         {Fore.GREEN}%%%%%%(      {Fore.RED}##,              {Fore.GREEN}#####   ######    #####    ##      ##        ##  ##    {Fore.RED}##\n"                 
    f"           {Fore.GREEN}*%%%%%%%%%%{Fore.RED}#                    {Fore.GREEN}##  ##       ##  ##    ##      ##  ##    ##  ##   {Fore.RED}####\n"                 
    f"                {Fore.GREEN}%%%%%%{Fore.RED}*               {Fore.GREEN}######    #####    #####   ####      ####    ###  ##  {Fore.RED}##  ##  {Fore.YELLOW}V1.0\n"                 
    f"                      {Fore.RED}#{Fore.YELLOW}\n"                 
)                                                                                     
   
   
def clear_screen():

    os.system('cls' if os.name == 'nt' else 'clear')


def search_regex(file_path, regex):
    matches = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        for line_number, line in enumerate(file, start=1):
            if re.search(regex, line):
                matches.append((line_number, line.strip()))
    return matches
    
    

def print_tree(directory, depth=0, keywords=None, regex=None, color=Fore.BLUE, folders_only=False, files_only=False, verbose=False, output_file=None, ignored_extensions=None, very_verbose=False, folders_verbose=None):
    try:
        items = os.listdir(directory)
    except PermissionError:
        print(f"{color}{Fore.RED}Permission denied : {directory}")
        return
    
    for i, item in enumerate(sorted(items)):
        full_path = os.path.join(directory, item)
        
        if os.path.isdir(full_path):
            if not files_only:
            
                if not folders_verbose:
            
                    print(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.YELLOW}{item}")
                    if output_file:
                        output_file.write(f"{'│   ' * depth}├── {item}\n")
                        
                else:
                    print(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.YELLOW}{full_path}")
                    if output_file:
                        output_file.write(f"{'│   ' * depth}├── {full_path}\n")                
            
            if not files_only and (ignored_extensions is None or not any(full_path.endswith(ext) for ext in ignored_extensions)):
                print_tree(full_path, depth + 1, keywords, regex, color, folders_only, files_only, verbose, output_file, ignored_extensions, very_verbose, folders_verbose)
        else:
            if not folders_only and (ignored_extensions is None or not any(full_path.endswith(ext) for ext in ignored_extensions)):
                if keywords or regex:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as file:
                    
                        if not very_verbose and not verbose:
                            if keywords:
                                print(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found {Fore.YELLOW}{keywords}{Fore.GREEN} into {Fore.YELLOW}{os.path.basename(full_path)}")
                                if output_file:
                                    output_file.write(f"{'│   ' * depth}├── Found '{keywords}' into {Fore.YELLOW}{os.path.basename(full_path)}\n")
                       
                            if regex:
                                matches = search_regex(full_path, regex)
                                for line in matches:
                                    print(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found pattern matching {Fore.YELLOW}{regex}{Fore.GREEN} into {Fore.YELLOW}{os.path.basename(full_path)}")
                                    if output_file:
                                        output_file.write(f"{'│   ' * depth}├── Found pattern matching '{regex}' into {os.path.basename(full_path)}\n")
                            
                        if verbose and not very_verbose:
                            for line_number, line in enumerate(file, start=1):
                                if keywords:
                                    for keyword in keywords:
                                        if keyword.lower() in line.lower():
                                            print(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found {Fore.YELLOW}{keyword} {Fore.GREEN}at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{os.path.basename(full_path)}")
                                            if output_file:
                                                output_file.write(f"{'│   ' * depth}├── Found '{keyword}' at line {line_number} in {os.path.basename(full_path)}\n")
                            if regex:
                                matches = search_regex(full_path, regex)
                                for line_number, line in matches:
                                    print(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found pattern matching {Fore.YELLOW}{regex}{Fore.GREEN} at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{os.path.basename(full_path)}")
                                    if output_file:
                                        output_file.write(f"{'│   ' * depth}├── Found pattern matching '{regex}' at line {line_number} in {os.path.basename(full_path)}\n")
                                    
                        if very_verbose:
                            for line_number, line in enumerate(file, start=1):
                                if keywords:
                                    for keyword in keywords:
                                        if keyword.lower() in line.lower():
                                            print(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found {Fore.YELLOW}{keyword}{Fore.GREEN} at {Fore.YELLOW}line {line_number} {Fore.GREEN}in {Fore.YELLOW}{os.path.basename(full_path)}")                                       
                                            if output_file:
                                                output_file.write(f"{'│   ' * depth}├── Found '{keyword}' at line {line_number} in {os.path.basename(full_path)}\n")
                                            if very_verbose:
                                                print(f"{color}{Style.BRIGHT}{'│   ' * depth}│   {Fore.CYAN}{line.strip()}")                             
                                                if output_file:
                                                    output_file.write(f"{'│   ' * depth}│   {line.strip()}\n")
                                                    
                            if regex:
                                matches = search_regex(full_path, regex)
                                for line_number, line in matches:
                                    print(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found pattern matching {Fore.YELLOW}{regex}{Fore.GREEN} at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{os.path.basename(full_path)}")
                                    if output_file:
                                        output_file.write(f"{'│   ' * depth}├── Found pattern matching '{regex}' at line {line_number} in {os.path.basename(full_path)}\n")

                                    print(f"{color}{Style.BRIGHT}{'│   ' * depth}│   {Fore.CYAN}{line.strip()}")
                                    if output_file:
                                        output_file.write(f"{'│   ' * depth}│   {line.strip()}\n")
                                            
                                            
                else:
                    print(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}{item}")
                    if output_file:
                        output_file.write(f"{'│   ' * depth}├── {item}\n")


# Args parse
def main():
    clear_screen()
    print(banner)
    parser = argparse.ArgumentParser(description=f"{Fore.GREEN}Search{Fore.RED}X{Fore.GREEN} - {Fore.BLUE}Advenced data finder{Fore.GREEN}")
    parser.add_argument("-usage", "--usage", action="store_true", help="Get usages exemple")
    parser.add_argument("-r", "--root", help="Root directory path to explore")#, required=True) # Par soucis d'estétique j'ai implémenté l'obligation différement
    parser.add_argument("-k", "--keywords", help="Keywords to search for in file names (separated by commas)")
    parser.add_argument("-x", "--regex", help="Regular expression to search for in file names. Example for a keyword followed by 3 digits: abc\d{3})")
    parser.add_argument("-d", "--folders-only", action="store_true", help="Display only folders")
    parser.add_argument("-dv", "--folders-verbose", action="store_true", help="Display fullpath folders")
    parser.add_argument("-f", "--files-only", action="store_true", help="Display only files in the target directory")
    parser.add_argument("-v", "--verbose", action="store_true", help="Display lines where keywords are found")
    parser.add_argument("-vv", "--very-verbose", action="store_true", help="Display all the text where keywords are found in line")
    parser.add_argument("-o", "--output", help="Save the results to a specified text file")
    parser.add_argument('-e', '--exclude', metavar='', type=str, help='Extensions to ignore separated by commas', default='')
    parser.add_argument('-i', '--ignore', action="store_true", help='ignore the following default extensions: .jpg, .png, .exe, .zip, .rar, .iso, .jpeg, .7z, .msi, .cap, .bin')
    args = parser.parse_args()

    keywords = args.keywords.split(",") if args.keywords else None # Gestion des recherches multiples par keywords

    if args.usage:
        print(f"\n{Fore.YELLOW}[Usages exemple]\n")
        print(f"{Fore.YELLOW}Search only 'password' keyword :\n   {Fore.GREEN}searchx.py -r C:/users -k password\n")
        print(f"{Fore.YELLOW}Search for the keywords 'pass', 'test', and 'hello' in full path, excluding files with extensions '.zip' and '.rar' :\n   {Fore.GREEN}searchx.py -r C:/users -k password,test,hello -dv -e .zip,.rar\n")
        print(f"{Fore.YELLOW}Search for the regex 'testXXX' where XXX represents numbers :\n   {Fore.GREEN}searchx.py -r C:/users -x " + "test\d{3}\n")
        print(f"{Fore.YELLOW}Show full path folders only :\n   {Fore.GREEN}searchx.py -r C:/users -d -dv\n")
        print(f"{Fore.YELLOW}Display the full path of folders containing the keywords 'password' and 'test', along with all text where these keywords are found in line, while ignoring default extensions :\n   {Fore.GREEN}searchx.py -r C:/users -k password,test -dv -i -vv\n")
        exit()
    
    if not args.root: # Gestion de l'obligation de l'argument --root
        print("\nUsage commands : searchx.py [-h] [--usage] [-r Directory] }[-k KEYWORDS] [-x REGEX] [-d] [-dv] [-f] [-v] [-vv] [-o OUTPUT] [-e] [-i]")
        exit()
 

 
    output_file = None
    if args.output:
        output_file = open(args.output, "w", encoding="utf-8")
        output_file.write(args.root + "\n") # Ajout dossier de recherche dans l'output
        
        
    # Gestion des filtres d'extensions
    ignored_extensions = None
    if args.exclude:
        ignored_extensions = args.exclude.split(',')
    else:
        ignored_extensions = None
        
    if args.ignore:
        default_ignored_extensions = ['.jpg', '.png', '.exe', '.zip', '.rar', '.iso', '.jpeg', '.7z', '.msi', '.cap', '.bin']
        if ignored_extensions:
            ignored_extensions += default_ignored_extensions
        else:
            ignored_extensions = default_ignored_extensions 
            
    very_verbose = args.very_verbose          
            

    print(Fore.YELLOW + args.root) # Ajout dossier de recherche
    print_tree(args.root, keywords=keywords, regex=args.regex, folders_only=args.folders_only, files_only=args.files_only, verbose=args.verbose, output_file=output_file, ignored_extensions=ignored_extensions, very_verbose=very_verbose, folders_verbose=args.folders_verbose)
    
    if output_file:
        output_file.close() # Fermeture du output en fin d'instruction
        
if __name__ == "__main__":
    main()




