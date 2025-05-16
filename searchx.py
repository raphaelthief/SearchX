# Of course, you're not going to use this tool to sift through ransomware leaks or any other crap. Don't be stupid and respect the law !
import os, re, argparse, json, requests, urllib3, sys, time, whois, pdfplumber, subprocess, logging, fitz
from pathlib import Path
from tqdm import tqdm
from wappalyzer import analyze
logging.getLogger("pdfminer").setLevel(logging.ERROR)

# dependencies
from Dependencies.holehe import check_holehe
from Dependencies.ignorant import check_ignorant
from Dependencies.phone_format import basicinfos
from Dependencies.scamsearch import scam
from Dependencies.ghunt import ghunter
from Dependencies.fbleaked import leaked
from Dependencies.leakcheck import leackcheck
from Dependencies.proxynova import proxynova1
from Dependencies.skype import skype
from Dependencies.breachdirectory import passwordtest
from Dependencies.blackbird import blackbirdhunt
from Dependencies.github import githubusername
from Dependencies.name_lastname import namesID
from Dependencies.iknowwhatyoudownload import torrents
from Dependencies.subdomain import subreponse
from Dependencies.ipinfos import ipinfo
from Dependencies.leakx import leakXx
from Dependencies.shodan import shodanit
from Dependencies.virustotal import check_ip_with_virustotal
from Dependencies.exploitfinder import initexploitdb, initialize_dorksdb, dorksearch
from Dependencies.cvesearch import searchcve
from Dependencies.whatweb import getwatweb
from Dependencies.twitter import tweetwho
from concurrent.futures import ThreadPoolExecutor
from Dependencies.whatsapp import getwhatsappinfos
from Dependencies.gitfive import gitfive_
from Dependencies.email_finder import find_emails
from Dependencies.vendorpassword import defaultpass
from Dependencies.metadatas import showme
from Dependencies.drive import drivehunt
from Dependencies.scamtel import getscamtel
from Dependencies.crawl_emails_phone import get_emails_phones
from Dependencies.lydia import proceed
from Dependencies.emailer import init_search
from Dependencies.breachvip import breachvip_init
from Dependencies.cybernews import init_cybernews
from Dependencies.annuaire import annuaire_search


# colorama
from colorama import init, Fore, Style

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
    f"                {Fore.GREEN}%%%%%%{Fore.RED}*               {Fore.GREEN}######    #####    #####   ####      ####    ###  ##  {Fore.RED}##  ##  {Fore.YELLOW}V1.2\n"                 
    f"                      {Fore.RED}#{Fore.YELLOW}\n"                 
)                                                                                     
   

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


all_files = []

def collect_files(directory, ignored_extensions=None):
    global all_files
    for root, _, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            if ignored_extensions is None or not any(full_path.endswith(ext) for ext in ignored_extensions):
                all_files.append(full_path)
    return all_files


def count_lines_in_file(file_path):
    
    total_lines = 0
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for _ in f:
                total_lines += 1
    except Exception as e:
        tqdm.write(f"{Fore.RED}Error reading file : {Fore.YELLOW}{file_path}")
        exit()
        
    return total_lines


def initialize_progress_bar(total):
    return tqdm(total=total, desc=f"{Fore.YELLOW}Scan progress ", unit="datas")


def update_progress(pbar):
    if pbar:
        pbar.update(1)



class TeeOutput:
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')  

    def __init__(self, filename):
        self.file = open(filename, 'a', encoding='utf-8')  
        self.stdout = sys.stdout  

    def write(self, text):
        self.stdout.write(text)  
        text_no_color = self.ansi_escape.sub('', text)  
        self.file.write(text_no_color)  

    def flush(self):
        self.stdout.flush()
        self.file.flush()

    def close(self):
        self.file.close()


#====================================== Program update ======================================
def git_pull():
    try:
        repo_path = os.getcwd()
        
        if not os.path.isdir(os.path.join(repo_path, ".git")):
            print("The current directory is not a Git repository (no .git folder found).")
            return

        os.chdir(repo_path)
        print(f"Git repository found: {repo_path}")

        command = ["git", "pull", "origin", "main"]
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode == 0:
            print(f"{Fore.YELLOW}[!] Done{Fore.GREEN}")
            print(result.stdout)
            # Check if the output indicates that changes were pulled
            if "Already up to date" not in result.stdout:
                print(f"{Fore.YELLOW}[!] Changes detected, restarting the script...{Fore.RESET}")
                os.execv(sys.executable, ['python'] + sys.argv)
        else:
            print(f"{Fore.RED}[!] Error :{Fore.GREEN}")
            print(result.stderr)

    except Exception as e:
        print(f"{Fore.RED}[!] Error : {Fore.GREEN}{e}")


#====================================== Local Search ======================================
def search_regex(text, regex, strict=None):
    matches = []

    if strict is not None:
        regex = rf'(?:^|[\s,:])({re.escape(strict)})\b'
        #regex = rf'\b{strict}\b'
    
    for line_number, line in enumerate(text.split('\n'), start=1):  
        if re.search(regex, line):
            matches.append((line_number, line.strip()))
    return matches
    
    
dirfileonly = [""]
def print_tree(directory, pbar=None, depth=0, keywords=None, regex=None, color=Fore.BLUE, strict=None, folders_only=False, files_only=False, verbose=False, ignored_extensions=None, very_verbose=False, folders_verbose=None):
    global dirfileonly
    
    if "file!" in directory:
        full_path = directory.replace("file!", "")
        if keywords or regex or strict:
            
            lines = []
            is_pdf = full_path.lower().endswith('.pdf')

            if is_pdf:
                try:
                    doc = fitz.open(full_path)
                    with initialize_progress_bar(len(doc)) as pbar:
                        for i in range(len(doc)):
                            update_progress(pbar)
                            page = doc[i]
                            text = page.get_text()
                            if text:
                                lines.extend(text.split('\n'))

                        if not very_verbose and not verbose:
                            found_keywords = set()
                            if keywords:
                                for line in lines:
                                    line_lower = line.lower()
                                    update_progress(pbar)
                                    for keyword in keywords:
                                        if keyword.lower() in line_lower:
                                            found_keywords.add(keyword)

                                if found_keywords:
                                    display_keywords = ", ".join(found_keywords)
                                    if files_only:
                                        tqdm.write(f"{color}{Style.BRIGHT}├── {Fore.GREEN}Found {Fore.YELLOW}{display_keywords} {Fore.GREEN}into {Fore.YELLOW}{full_path}")
                                    else:
                                        tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found {Fore.YELLOW}{display_keywords} {Fore.GREEN}into {Fore.YELLOW}{os.path.basename(full_path)}")

                            if regex or strict:
                                matches = search_regex('\n'.join(lines), regex, strict)
                                if strict:
                                    regex = strict

                                for line in matches:
                                    update_progress(pbar)
                                    if files_only:
                                        tqdm.write(f"{color}{Style.BRIGHT}├── {Fore.GREEN}Found {Fore.YELLOW}{keywords}{Fore.GREEN} into {Fore.YELLOW}{full_path}")
                                    else:    
                                        tqdm.write(f"{color}{Style.BRIGHT}├── {Fore.GREEN}Found {Fore.YELLOW}{keywords}{Fore.GREEN} into {Fore.YELLOW}{os.path.basename(full_path)}")

                        if verbose and not very_verbose:
                            for line_number, line in enumerate(lines, start=1):
                                line_lower = line.lower()
                                update_progress(pbar)
                                if keywords:
                                    for keyword in keywords:
                                        if keyword.lower() in line_lower:
                                            if files_only:
                                                tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found {Fore.YELLOW}{keyword} {Fore.GREEN}at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{full_path}")
                                            else:
                                                tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found {Fore.YELLOW}{keyword} {Fore.GREEN}at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{os.path.basename(full_path)}")

                            if regex or strict:
                                matches = search_regex('\n'.join(lines), regex, strict)
                                if strict:
                                    regex = strict
                                    
                                for line_number, line in matches:
                                    update_progress(pbar)
                                    if files_only:
                                        tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found pattern matching {Fore.YELLOW}{regex}{Fore.GREEN} at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{full_path}")
                                    else:    
                                        tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found pattern matching {Fore.YELLOW}{regex}{Fore.GREEN} at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{os.path.basename(full_path)}")

                        if very_verbose:
                            for line_number, line in enumerate(lines, start=1): 
                                line_lower = line.lower()
                                update_progress(pbar)
                                if keywords:
                                    for keyword in keywords:
                                        if keyword.lower() in line_lower:
                                            if files_only:
                                                tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found {Fore.YELLOW}{keyword}{Fore.GREEN} at {Fore.YELLOW}line {line_number} {Fore.GREEN}in {Fore.YELLOW}{full_path}")
                                            else:    
                                                tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found {Fore.YELLOW}{keyword}{Fore.GREEN} at {Fore.YELLOW}line {line_number} {Fore.GREEN}in {Fore.YELLOW}{os.path.basename(full_path)}")                                       
                                           
                                            if very_verbose:
                                                tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}│   {Fore.CYAN}{line}")                             
                                    
                            if regex or strict:
                                matches = search_regex('\n'.join(lines), regex, strict)
                                if strict:
                                    regex = strict
                                    
                                for line_number, line in matches:
                                    update_progress(pbar)
                                    if files_only:
                                        tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found pattern matching {Fore.YELLOW}{regex}{Fore.GREEN} at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{full_path}")
                                    else:    
                                        tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found pattern matching {Fore.YELLOW}{regex}{Fore.GREEN} at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{os.path.basename(full_path)}")
                                   
                                    tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}│   {Fore.CYAN}{line}")


                except pdfplumber.utils.exceptions.PdfminerException as e:
                    tqdm.write(f"{color}{Style.BRIGHT}├── {Fore.RED}Error reading PDF file (pdfplumber) : {Fore.YELLOW}{full_path}")
                    exit()

                except Exception as e:
                    tqdm.write(f"{color}{Style.BRIGHT}├── {Fore.RED}Error reading PDF file : {Fore.YELLOW}{full_path}")
                    exit()
                
            else:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as file:
                    lines = file.readlines()
                 
                count_lines_file = count_lines_in_file(full_path)
                with initialize_progress_bar(count_lines_file) as pbar:
                    if not very_verbose and not verbose:
                        found_keywords = set()
                        if keywords:
                            for line in lines:
                                line_lower = line.lower()
                                update_progress(pbar)
                                for keyword in keywords:
                                    if keyword.lower() in line_lower:
                                        found_keywords.add(keyword)

                            if found_keywords:
                                display_keywords = ", ".join(found_keywords)
                                if files_only:
                                    tqdm.write(f"{color}{Style.BRIGHT}├── {Fore.GREEN}Found {Fore.YELLOW}{display_keywords} {Fore.GREEN}into {Fore.YELLOW}{full_path}")
                                else:
                                    tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found {Fore.YELLOW}{display_keywords} {Fore.GREEN}into {Fore.YELLOW}{os.path.basename(full_path)}")

                        if regex or strict:
                            matches = search_regex('\n'.join(lines), regex, strict)
                            if strict:
                                regex = strict

                            for line in matches:
                                update_progress(pbar)
                                if files_only:
                                    tqdm.write(f"{color}{Style.BRIGHT}├── {Fore.GREEN}Found {Fore.YELLOW}{keywords}{Fore.GREEN} into {Fore.YELLOW}{full_path}")
                                else:    
                                    tqdm.write(f"{color}{Style.BRIGHT}├── {Fore.GREEN}Found {Fore.YELLOW}{keywords}{Fore.GREEN} into {Fore.YELLOW}{os.path.basename(full_path)}")

                    if verbose and not very_verbose:
                        for line_number, line in enumerate(lines, start=1):
                            line_lower = line.lower()
                            update_progress(pbar)
                            if keywords:
                                for keyword in keywords:
                                    if keyword.lower() in line_lower:
                                        if files_only:
                                            tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found {Fore.YELLOW}{keyword} {Fore.GREEN}at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{full_path}")
                                        else:
                                            tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found {Fore.YELLOW}{keyword} {Fore.GREEN}at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{os.path.basename(full_path)}")

                        if regex or strict:
                            matches = search_regex('\n'.join(lines), regex, strict)
                            if strict:
                                regex = strict
                                
                            for line_number, line in matches:
                                update_progress(pbar)
                                if files_only:
                                    tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found pattern matching {Fore.YELLOW}{regex}{Fore.GREEN} at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{full_path}")
                                else:    
                                    tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found pattern matching {Fore.YELLOW}{regex}{Fore.GREEN} at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{os.path.basename(full_path)}")

                    if very_verbose:
                        for line_number, line in enumerate(lines, start=1):
                            line_lower = line.lower()
                            update_progress(pbar)
                            if keywords:
                                for keyword in keywords:
                                    if keyword.lower() in line_lower:
                                        if files_only:
                                            tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found {Fore.YELLOW}{keyword}{Fore.GREEN} at {Fore.YELLOW}line {line_number} {Fore.GREEN}in {Fore.YELLOW}{full_path}")
                                        else:    
                                            tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found {Fore.YELLOW}{keyword}{Fore.GREEN} at {Fore.YELLOW}line {line_number} {Fore.GREEN}in {Fore.YELLOW}{os.path.basename(full_path)}")                                       
                                       
                                        if very_verbose:
                                            tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}│   {Fore.CYAN}{line}")                             
                                
                        if regex or strict:
                            matches = search_regex('\n'.join(lines), regex, strict)
                            if strict:
                                regex = strict
                                
                            for line_number, line in matches:
                                update_progress(pbar)
                                if files_only:
                                    tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found pattern matching {Fore.YELLOW}{regex}{Fore.GREEN} at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{full_path}")
                                else:    
                                    tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found pattern matching {Fore.YELLOW}{regex}{Fore.GREEN} at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{os.path.basename(full_path)}")
                               
                                tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}│   {Fore.CYAN}{line}")
           
        else:
            tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}{item}")

    else:
        
        try:
            items = os.listdir(directory)
        except PermissionError:
            tqdm.write(f"{color}{Fore.RED}Permission denied : {directory}")
            return
        
        for i, item in enumerate(sorted(items)):
            full_path = os.path.join(directory, item)
            
            if os.path.isdir(full_path):
                if not files_only:
                
                    if not folders_verbose:
                
                        tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.YELLOW}{item}")
                        
                    else:
                        tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.YELLOW}{full_path}")
                        
                if (ignored_extensions is None or not any(full_path.endswith(ext) for ext in ignored_extensions)): #if not files_only and (ignored_extensions is None or not any(full_path.endswith(ext) for ext in ignored_extensions)):
                    print_tree(full_path, pbar, depth + 1, keywords, regex, color, strict, folders_only, files_only, verbose, ignored_extensions, very_verbose, folders_verbose)
            else:
                if not folders_only and (ignored_extensions is None or not any(full_path.endswith(ext) for ext in ignored_extensions)):
                    
                    if keywords or regex or strict:

                        lines = []
                        is_pdf = full_path.lower().endswith('.pdf')

                        if is_pdf:
                            try:
                                with pdfplumber.open(full_path) as pdf:
                                    for page in pdf.pages:
                                        text = page.extract_text()
                                        if text:
                                            lines.extend(text.split('\n'))
                            except pdfplumber.utils.exceptions.PdfminerException as e:
                                tqdm.write(f"{color}{Style.BRIGHT}├── {Fore.RED}Error reading PDF file (pdfplumber) : {Fore.YELLOW}{full_path}")
                            except Exception as e:
                                tqdm.write(f"{color}{Style.BRIGHT}├── {Fore.RED}Error reading PDF file : {Fore.YELLOW}{full_path}")
                    

                            if not very_verbose and not verbose:
                                found_keywords = set()
                                if keywords:
                                    for line in lines:
                                        line_lower = line.lower()
                                        for keyword in keywords:
                                            if keyword.lower() in line_lower:
                                                found_keywords.add(keyword)

                                    if found_keywords:
                                        display_keywords = ", ".join(found_keywords)
                                        if files_only:
                                            tqdm.write(f"{color}{Style.BRIGHT}├── {Fore.GREEN}Found {Fore.YELLOW}{display_keywords} {Fore.GREEN}into {Fore.YELLOW}{full_path}")
                                        else:
                                            tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found {Fore.YELLOW}{display_keywords} {Fore.GREEN}into {Fore.YELLOW}{os.path.basename(full_path)}")
                                            

                                if regex or strict:
                                    matches = search_regex('\n'.join(lines), regex, strict)
                                    if strict:
                                        regex = strict

                                    for line in matches:
                                        if files_only:
                                            tqdm.write(f"{color}{Style.BRIGHT}├── {Fore.GREEN}Found {Fore.YELLOW}{keywords}{Fore.GREEN} into {Fore.YELLOW}{full_path}")
                                        else:    
                                            tqdm.write(f"{color}{Style.BRIGHT}├── {Fore.GREEN}Found {Fore.YELLOW}{keywords}{Fore.GREEN} into {Fore.YELLOW}{os.path.basename(full_path)}")
                                
                            if verbose and not very_verbose:
                                for line_number, line in enumerate(lines, start=1):
                                    line_lower = line.lower()
                                    if keywords:
                                        for keyword in keywords:
                                            if keyword.lower() in line_lower:
                                                if files_only:
                                                    tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found {Fore.YELLOW}{keyword} {Fore.GREEN}at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{full_path}")
                                                else:
                                                    tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found {Fore.YELLOW}{keyword} {Fore.GREEN}at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{os.path.basename(full_path)}")
                                                
                                if regex or strict:
                                    matches = search_regex('\n'.join(lines), regex, strict)
                                    if strict:
                                        regex = strict
                                        
                                    for line_number, line in matches:
                                        if files_only:
                                            tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found pattern matching {Fore.YELLOW}{regex}{Fore.GREEN} at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{full_path}")
                                        else:    
                                            tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found pattern matching {Fore.YELLOW}{regex}{Fore.GREEN} at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{os.path.basename(full_path)}")
                                        
                            if very_verbose:
                                for line_number, line in enumerate(lines, start=1):
                                    line_lower = line.lower()
                                    if keywords:
                                        for keyword in keywords:
                                            if keyword.lower() in line_lower:
                                                if files_only:
                                                    tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found {Fore.YELLOW}{keyword}{Fore.GREEN} at {Fore.YELLOW}line {line_number} {Fore.GREEN}in {Fore.YELLOW}{full_path}")
                                                else:    
                                                    tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found {Fore.YELLOW}{keyword}{Fore.GREEN} at {Fore.YELLOW}line {line_number} {Fore.GREEN}in {Fore.YELLOW}{os.path.basename(full_path)}")                                       
                                               
                                                if very_verbose:
                                                    tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}│   {Fore.CYAN}{line}")                             
                                    
                                    update_progress(pbar)
                                        
                                if regex or strict:
                                    matches = search_regex('\n'.join(lines), regex, strict)
                                    if strict:
                                        regex = strict
                                        
                                    for line_number, line in matches:
                                        if files_only:
                                            tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found pattern matching {Fore.YELLOW}{regex}{Fore.GREEN} at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{full_path}")
                                        else:    
                                            tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found pattern matching {Fore.YELLOW}{regex}{Fore.GREEN} at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{os.path.basename(full_path)}")
                                       
                                        tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}│   {Fore.CYAN}{line}")
                                                

                        else:
                            with open(full_path, 'r', encoding='utf-8', errors='ignore') as file:
                                lines = file.readlines()
                        
                            if not very_verbose and not verbose:
                                found_keywords = set()
                                if keywords:
                                    for line in lines:
                                        line_lower = line.lower()
                                        for keyword in keywords:
                                            if keyword.lower() in line_lower:
                                                found_keywords.add(keyword)

                                    if found_keywords:
                                        display_keywords = ", ".join(found_keywords)
                                        if files_only:
                                            tqdm.write(f"{color}{Style.BRIGHT}├── {Fore.GREEN}Found {Fore.YELLOW}{display_keywords} {Fore.GREEN}into {Fore.YELLOW}{full_path}")
                                        else:
                                            tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found {Fore.YELLOW}{display_keywords} {Fore.GREEN}into {Fore.YELLOW}{os.path.basename(full_path)}")
                                            
                                if regex or strict:
                                    matches = search_regex('\n'.join(lines), regex, strict)
                                    if strict:
                                        regex = strict
                                    if matches:
                                        if files_only:
                                            tqdm.write(f"{color}{Style.BRIGHT}├── {Fore.GREEN}Found {Fore.YELLOW}{regex}{Fore.GREEN} into {Fore.YELLOW}{full_path}")
                                        else:    
                                            tqdm.write(f"{color}{Style.BRIGHT}├── {Fore.GREEN}Found {Fore.YELLOW}{regex}{Fore.GREEN} into {Fore.YELLOW}{os.path.basename(full_path)}")

                            if verbose and not very_verbose:
                                for line_number, line in enumerate(lines, start=1):
                                    line_lower = line.lower()
                                    if keywords:
                                        for keyword in keywords:
                                            if keyword.lower() in line_lower:
                                                if files_only:
                                                    tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found {Fore.YELLOW}{keyword} {Fore.GREEN}at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{full_path}")
                                                else:
                                                    tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found {Fore.YELLOW}{keyword} {Fore.GREEN}at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{os.path.basename(full_path)}")
                                                
                                if regex or strict:
                                    matches = search_regex('\n'.join(lines), regex, strict)
                                    if strict:
                                        regex = strict
                                        
                                    for line_number, line in matches:
                                        if files_only:
                                            tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found pattern matching {Fore.YELLOW}{regex}{Fore.GREEN} at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{full_path}")
                                        else:    
                                            tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found pattern matching {Fore.YELLOW}{regex}{Fore.GREEN} at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{os.path.basename(full_path)}")
                                        
                            if very_verbose:
                                for line_number, line in enumerate(lines, start=1):
                                    line_lower = line.lower()
                                    if keywords:
                                        for keyword in keywords:
                                            if keyword.lower() in line_lower:
                                                if files_only:
                                                    tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found {Fore.YELLOW}{keyword}{Fore.GREEN} at {Fore.YELLOW}line {line_number} {Fore.GREEN}in {Fore.YELLOW}{full_path}")
                                                else:    
                                                    tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found {Fore.YELLOW}{keyword}{Fore.GREEN} at {Fore.YELLOW}line {line_number} {Fore.GREEN}in {Fore.YELLOW}{os.path.basename(full_path)}")                                       
                                               
                                                if very_verbose:
                                                    tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}│   {Fore.CYAN}{line.strip()}")                             

                                if regex or strict:
                                    matches = search_regex('\n'.join(lines), regex, strict)
                                    if strict:
                                        regex = strict
                                        
                                    for line_number, line in matches:
                                        if files_only:
                                            tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found pattern matching {Fore.YELLOW}{regex}{Fore.GREEN} at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{full_path}")
                                        else:    
                                            tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}Found pattern matching {Fore.YELLOW}{regex}{Fore.GREEN} at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{os.path.basename(full_path)}")
                                       
                                        tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}│   {Fore.CYAN}{line.strip()}")
                                                
                    else:
                        tqdm.write(f"{color}{Style.BRIGHT}{'│   ' * depth}├── {Fore.GREEN}{item}")
                      
                update_progress(pbar)


#====================================== MultiThreading ======================================

# Function to search for a keyword in a file
def search_keyword_in_file(file, keywords=None, very_verbose=False, verbose=False):
    try:
        color=Fore.BLUE
        
        is_pdf = file.lower().endswith('.pdf')
        lines = []        

        if is_pdf:
            try:
                with pdfplumber.open(file) as pdf:
                    for page in pdf.pages:
                        text = page.extract_text()
                        if text:
                            lines.extend(text.split('\n'))
            except PdfminerException as e:
                print(f"{Fore.RED}[PDF error] {file}: {e}")
            except Exception as e:
                print(f"{Fore.RED}[Unknown PDF error] {file}: {e}")

        else:
            with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.read().splitlines()
                
                
        found = False
        for line_number, line in enumerate(lines, start=1):
            for keyword in keywords:
                if keyword.lower() in line.lower():
                    found = True
                    
                    if very_verbose:
                        print(f"{color}{Style.BRIGHT}├── {Fore.GREEN}Found {Fore.YELLOW}{keyword} {Fore.GREEN}at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{file}")
                        print(f"{color}{Style.BRIGHT}│   {Fore.CYAN}{line.strip()}")
                    elif verbose:
                        print(f"{color}{Style.BRIGHT}├── {Fore.GREEN}Found {Fore.YELLOW}{keyword} {Fore.GREEN}at line {Fore.YELLOW}{line_number} {Fore.GREEN}in {Fore.YELLOW}{file}")
                    
        if found and not verbose and not very_verbose:
            print(f"{color}{Style.BRIGHT}├── {Fore.GREEN}Found {Fore.YELLOW}{keywords} {Fore.GREEN}in {Fore.YELLOW}{file}")
                    
    except Exception as e:
        pass

# Function to walk through directories and files
def walk_through_directories(directory, keywords=None, num_threads=10, very_verbose=False, verbose=False, ignored_extensions=None):
    try:
        start_time = time.time()
        files_to_process = []
        # Walk through all subdirectories and files in the given directory
        for root, subdirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Skip files with ignored extensions
                if ignored_extensions:
                    file_extension = os.path.splitext(file)[1].lower()
                    if file_extension in ignored_extensions:
                        continue  # Skip this file and move to the next one

                files_to_process.append(file_path)
        
        # Create a thread pool with the specified number of threads
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            # Launch the search in each file
            executor.map(lambda file: search_keyword_in_file(file, keywords, very_verbose=very_verbose, verbose=verbose), files_to_process)
        
        elapsed_time = time.time() - start_time
        formatted_time = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))
        print(f"{Fore.YELLOW}[!] Elapsed time : {Fore.GREEN}{formatted_time} ({elapsed_time:.2f} seconds)")
    except Exception as e:
        pass


#====================================== Main ======================================
def main():
    try:
        clear_screen()
        print(banner)
        parser = argparse.ArgumentParser(description=f"{Fore.GREEN}Search{Fore.RED}X{Fore.GREEN} - {Fore.BLUE}Advenced data finder{Fore.GREEN}")
        parser.add_argument("-usage", "--usage", action="store_true", help="Get usages exemple")
        parser.add_argument("-u", "--update", action="store_true", help="get updates")
        parser.add_argument('--ip',  help='search infos through ip, domain, ... (iknowwhatyoudownload, whois, leakix, ...)')
        parser.add_argument('--subdomain',  help='search subdomain of a spoecific host (leakix request)')
        parser.add_argument('--version',  help='search webapp technologies with wappalyzer module')
        parser.add_argument('--comb',  help='search through the COMB leak via an API (proxynova)')
        parser.add_argument('--skype',  help='search through skype (skypesearch)')
        parser.add_argument('--email',  help='search emails match (holehe)')
        parser.add_argument('--phone',  help='search phone match')
        parser.add_argument('--username',  help='search username (blackbird)')
        parser.add_argument('--name',  help='search first and last name (--lastname needed)')
        parser.add_argument('--lastname',  help='search first and last name (--name needed)')
        parser.add_argument('--where',  help='search first and last name with location (--name & --lastname needed)')
        parser.add_argument('--exploit', nargs='*', help='Search for vulnerabilities (--exploit "description" "CVE-ID" "port_number" : --exploit "eternalblue" OR --exploit "eternalblue" "" "445")')
        parser.add_argument('--dorks',  help='Search for Google Dorks (--dorks "index off")')
        parser.add_argument('--cve', nargs='*', help='Search for cve (--cve "search query" "CVE-ID")')
        parser.add_argument('-p', '--password',  help='check how many times this password has been leaked (breachdirectory)')
        parser.add_argument("--tweet", help="Find tweets, posts, etc... by usernames even if the profile was deleted (wayback urls)")
        parser.add_argument("-ef", "--emailfinder", help="Find valid email with firstname lastname & domain (ex : 'john doe gmail.com')")
        parser.add_argument("-def", "--defaultpassword", help="Find default devices passwords")
        parser.add_argument("-meta", "--metadatas", help=r"Search for metadas on DS_Store, pdf, docx, etc .... (ex : --metadatas 'E:\something\some folder\.DS_store'")
        parser.add_argument("-dh", "--drivehunt", help=r"Search for metadas on Google Drive document with xeuledoc(ex : -dh https://docs.google.com/spreadsheets/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms)")
        parser.add_argument("--crawl", help="Search for stored infos (emails and phone numbers) in a webpage")
        parser.add_argument("-r", "--root", help="Root directory path to explore")#, required=True) # aesthetic bug fix
        parser.add_argument("-rf", "--rootfile", help="Specific file to explore (only one file)")#, required=True) # aesthetic bug fix
        parser.add_argument("-k", "--keywords", help="Keywords to search for in file names (separated by commas)")
        parser.add_argument("-x", "--regex", help=r"Regular expression to search for in file names. Example for a keyword followed by 3 digits: abc\d{3})")
        parser.add_argument("-kx", "--strict", help="Search for an exact keyword, ensuring it is preceded by specific characters (':', ' ', ',' or start of the line), ensuring no partial matches")
        parser.add_argument("-d", "--folders-only", action="store_true", help="Display only folders")
        parser.add_argument("-dv", "--folders-verbose", action="store_true", help="Display fullpath folders")
        parser.add_argument("-f", "--files-only", action="store_true", help="Display only matched files ")
        parser.add_argument("-v", "--verbose", action="store_true", help="Display lines where keywords are found")
        parser.add_argument("-vv", "--very-verbose", action="store_true", help="Display all the text where keywords are found in line")
        parser.add_argument("-o", "--output", help="Save the results to a specified text file")
        parser.add_argument('-e', '--exclude', metavar='', type=str, help='Extensions to ignore separated by commas', default='')
        parser.add_argument('-i', '--ignore', action="store_true", help='ignore the following default extensions: .jpg, .png, .exe, .zip, .rar, .iso, .jpeg, .7z, .msi, .cap, .bin')
        parser.add_argument("-t", "--threads", type=int, help="Multi threading. Works automatically with the -f argument. You need to provide -k argument(s). Optionals args allowed : -v -vv -i -e | Fast mode works only with -v -vv -k -i -e")

        
        args = parser.parse_args()


        keywords = args.keywords.split(",") if args.keywords else None


        if len(sys.argv) == 1:
            parser.print_usage()
            sys.exit(0)


        if any([args.keywords, args.regex, args.strict, args.folders_only, args.files_only, args.verbose, args.very_verbose, args.exclude, args.ignore]) and not (args.root or args.rootfile):
            print(f"{Fore.YELLOW}[!] {Fore.RED}[-r ROOT] or [-rf ROOTFILE] argument missing{Fore.YELLOW}\n")
            parser.print_usage()
            sys.exit(0)


        print(f"{Fore.YELLOW}[!] Command executed : {' '.join(sys.argv)}\n")
        

        if args.update:
            git_pull()


        if args.usage:

            print(f"\n{Fore.YELLOW}[Usages exemple]")
            print(f"{Fore.YELLOW}---------------------------------------------------------------------------\n{Fore.GREEN}")
            print(f"{Fore.YELLOW}[+] Set token.txt to search a user with --skype :\n    {Fore.GREEN}searchx.py --skype exemple@exemple.com")
            print(f"{Fore.YELLOW}[+] Search for Facebook, Copains d'avant, wattpad, annonces mortuaires, pages blanches, bac, brevet, ... :\n    {Fore.GREEN}searchx.py --name NAME --lastname LASTNAME")
            print(f"{Fore.YELLOW}[+] Search for phone number --phone +PHONECODE_PHONENUMBER (use phone code with '+') :\n    {Fore.GREEN}searchx.py --phone +33633894568\n    searchx.py --phone +330633894568")
            print(f"{Fore.YELLOW}[+] Search for email infos :\n    {Fore.GREEN}searchx.py --email exemple@gmail.com")
            print(f"{Fore.YELLOW}[+] Search for ip infos :\n    {Fore.GREEN}searchx.py --ip <ip>")
            print(f"{Fore.YELLOW}[+] Search for leaked infos into COMB db :\n    {Fore.GREEN}searchx.py --comb <search_query>")
            print(f"{Fore.YELLOW}[+] Search for DNS & subdomains infos :\n    {Fore.GREEN}searchx.py --subdomain <ip or DNS>")
            print(f"{Fore.YELLOW}[+] Search for username infos :\n    {Fore.GREEN}searchx.py --username <username>")
            print(f"{Fore.YELLOW}[+] Search for Google Dorks :\n    {Fore.GREEN}searchx.py --dorks <search_query>")
            print(f"{Fore.YELLOW}[+] Search for exploits :\n    {Fore.GREEN}searchx.py --exploit 'description' 'CVE-ID' 'port_number' | searchx.py --exploit 'eternalblue' | searchx.py --exploit 'eternalblue' '' '445'")
            print(f"{Fore.YELLOW}[+] Search for CVE :\n    {Fore.GREEN}searchx.py --cve 'search_query' 'CVE_ID' | searchx.py --cve 'eternalblue' | searchx.py --cve '' 'CVE-2024_16738'")
            
            print(f"{Fore.YELLOW}    \n---------------------------------------------------------------------------\n{Fore.GREEN}")
            
            print(f"{Fore.YELLOW}[+] Search only 'password' keyword :\n    {Fore.GREEN}searchx.py -r C:/users -k password")
            print(f"{Fore.YELLOW}[+] Search for the keywords 'pass', 'test', and 'hello' in full path, excluding files with extensions '.zip' and '.rar' :\n    {Fore.GREEN}searchx.py -r C:/users -k password,test,hello -dv -e .zip,.rar")
            print(f"{Fore.YELLOW}[+] Search for the regex 'testXXX' where XXX represents numbers :\n    {Fore.GREEN}searchx.py -r C:/users -x " + r"test\d{3}")
            print(f"{Fore.YELLOW}[+] Show full path folders only :\n    {Fore.GREEN}searchx.py -r C:/users -d -dv")
            print(f"{Fore.YELLOW}[+] Display the full path of folders containing the keywords 'password' and 'test', along with all text where these keywords are found in line, while ignoring default extensions :\n    {Fore.GREEN}searchx.py -r C:/users -k password,test -dv -i -vv")
            print(f"{Fore.YELLOW}[+] Search through one file :\n    {Fore.GREEN}searchx.py -rf C:/users/file.txt -k <keyword> -vv")
            print(f"{Fore.YELLOW}[+] Search for keywords and display only the files found that match one of the keywords, showing the full file path and its content :\n    {Fore.GREEN}searchx.py -r C:/users/path  -k <keyword1,keyword2> -dv -vv -f")

            exit()


        output_file = None
        if args.output:
            sys.stdout = TeeOutput(args.output)


        if args.tweet:
            print(f"{Fore.YELLOW}[!] Searching twitter(X) posts [{Fore.GREEN}{args.tweet}{Fore.YELLOW}]")
            tweetwho(args.tweet)


        if args.emailfinder:
            try:
                first_name, last_name, domain = args.emailfinder.split()
                print(f"{Fore.YELLOW}[!] Searching valid emails for [{Fore.GREEN}{args.emailfinder}{Fore.YELLOW}]")
                find_emails(first_name, last_name, domain)
            except ValueError:
                print(f"{Fore.RED}Invalid input format. Please provide arguments in the format : {Fore.YELLOW}'firstname lastname domain'")
            
            
        if args.defaultpassword:
            print(f"{Fore.YELLOW}[!] Searching default password for [{Fore.GREEN}{args.defaultpassword}{Fore.YELLOW}] (https://cirt.net/)\n{Fore.YELLOW}------------------{Fore.GREEN}")
            defaultpass(args.defaultpassword)
            

        if args.metadatas:
            print(f"{Fore.YELLOW}[!] Searching for metadatas to file [{Fore.GREEN}{args.metadatas}{Fore.YELLOW}]\n")
            showme(args.metadatas)


        if args.drivehunt:
            print(f"{Fore.YELLOW}[!] Searching for metadatas to drive document [{Fore.GREEN}{args.drivehunt}{Fore.YELLOW}] (https://github.com/Malfrats/xeuledoc)\n")
            drivehunt(args.drivehunt)
            

        if args.crawl:
            print(f"{Fore.YELLOW}[!] Searching for emails and phone numbers [{Fore.GREEN}{args.crawl}{Fore.YELLOW}]")
            get_emails_phones(args.crawl)


        if args.skype:
            try:
                print(f"{Fore.YELLOW}----- Credit to : {Fore.GREEN}https://github.com/Totoro2205/SkypeSearch{Fore.YELLOW} -----{Fore.GREEN}")
                skype(args.skype, 'Tokens/skype_token.txt')
                
            except KeyboardInterrupt:
                print(f"\n{Fore.RED}[!] KeyboardInterrupt...\n{Fore.YELLOW}[!] End of search")
                sys.exit(0)
            
            
        if args.comb:
            try:
                print(f"{Fore.YELLOW}----- Connect db api : {Fore.GREEN}https://www.proxynova.com/{Fore.YELLOW} -----")
                proxynova1(args.comb)
           
            except KeyboardInterrupt:
                print(f"\n{Fore.RED}[!] KeyboardInterrupt...\n{Fore.YELLOW}[!] End of search")
                sys.exit(0)
                
           
        if args.password:
            print(f"{Fore.YELLOW}----- Connect db api : {Fore.GREEN}https://breachdirectory.org/passwords{Fore.YELLOW} -----")
            passwordtest(args.password)

            print(f"\n{Fore.YELLOW}----- Launching breachvip research -----")
            breachvip_init(args.password, "Password")

        if args.email:
            try:
                print(f"{Fore.YELLOW}----- Launching holehe : {Fore.GREEN}https://github.com/megadose/holehe{Fore.YELLOW} -----")
                print(f"[!] Checking dependencies ...")
                check_holehe(args.email)
                
                print(f"\n{Fore.YELLOW}----- Launching Blackbird : {Fore.GREEN}https://github.com/p1ngul1n0/blackbird{Fore.YELLOW} -----")
                blackbirdhunt(args.email, "email")
                
                leackcheck(args.email)
                init_cybernews(args.email, "email")
                
                scam(args.email)

                print(f"\n{Fore.YELLOW}----- Launching GitFive : {Fore.GREEN}https://github.com/mxrch/GitFive{Fore.YELLOW} -----")
                gitfive_(args.email, "email")

                print(f"\n{Fore.YELLOW}----- Launching Ghunt : {Fore.GREEN}https://github.com/mxrch/GHunt{Fore.YELLOW} -----")
                ghunter(args.email)

                print(f"\n{Fore.YELLOW}----- Launching searchX research -----")
                init_search(args.email, "email")
                
                print(f"\n{Fore.YELLOW}----- Launching breachvip research -----")
                breachvip_init(args.email, "Email")
                
                print(f"\n{Fore.YELLOW}[!] Urls to visit")
                print(f"{Fore.YELLOW}--> {Fore.GREEN}https://epieos.com/")
                print(f"{Fore.YELLOW}--> {Fore.GREEN}https://haveibeenpwned.com/")
                print(f"{Fore.YELLOW}--> {Fore.GREEN}https://breachdirectory.org/")
                print(f"{Fore.YELLOW}--> {Fore.GREEN}https://cybernews.com/personal-data-leak-check/")
                print(f"{Fore.YELLOW}--> {Fore.GREEN}https://breach.vip/")
                print(f"{Fore.YELLOW}--> {Fore.GREEN}https://oathnet.ru/")
                print(f"{Fore.YELLOW}--> {Fore.GREEN}https://dehashed.com/")
                print(f"{Fore.YELLOW}--> {Fore.GREEN}https://vxintelligence.com/")
                print(f"{Fore.YELLOW}--> {Fore.GREEN}https://leakpeek.com/")
                
            
            except KeyboardInterrupt:
                print(f"\n{Fore.RED}[!] KeyboardInterrupt...\n{Fore.YELLOW}[!] End of search")
                sys.exit(0)
            
            
        if args.username:
            try:
                print(f"{Fore.YELLOW}----- Launching blackbird : {Fore.GREEN}https://github.com/p1ngul1n0/blackbird{Fore.YELLOW} -----")
                print(f"[!] Checking dependencies ...")
                blackbirdhunt(args.username, "username")
                githubusername(args.username)

                print(f"\n{Fore.YELLOW}----- Launching GitFive : {Fore.GREEN}https://github.com/mxrch/GitFive{Fore.YELLOW} -----")
                gitfive_(args.username, "username")

                print(f"\n{Fore.YELLOW}----- Launching searchX research -----")
                init_search(args.username, "username")

                print(f"\n{Fore.YELLOW}----- Launching breachvip research -----")
                breachvip_init(args.username, "Username")
                
                leackcheck(args.username)
                
                print(f"\n{Fore.YELLOW}[!] Urls to visit")
                print(f"{Fore.YELLOW}--> {Fore.GREEN}https://vxintelligence.com/")

            except KeyboardInterrupt:
                print(f"\n{Fore.RED}[!] KeyboardInterrupt...\n{Fore.YELLOW}[!] End of search")
                sys.exit(0)
                
            
        if (args.name and not args.lastname) or (args.lastname and not args.name):
            print(f"{Fore.RED}Error : Launching social medias fail. args --name and --lastname needed\n")

        if args.where:
            if not (args.name and args.lastname):
                print(f"{Fore.RED}Error : args --name and --lastname needed\n")
            else:
                print(f"{Fore.YELLOW}----- Launching 118000 annuaire search -----")
                annuaire_search(args.lastname, args.name, args.where)

        if args.name and args.lastname:
            try:
                print(f"{Fore.YELLOW}----- Launching social medias : {Fore.GREEN}instagram, facebook, twitter, linkedin{Fore.YELLOW} -----")
                namesID(args.name, args.lastname)

                print(f"\n{Fore.YELLOW}----- Launching breachvip research -----")
                breachvip_init(args.lastname, "Name")

            except KeyboardInterrupt:
                print(f"\n{Fore.RED}[!] KeyboardInterrupt...\n{Fore.YELLOW}[!] End of search")
                sys.exit(0)
                

        if args.phone:
            try:

                basicinfos(args.phone)
                print(f"{Fore.YELLOW}----- Launching ignorant : {Fore.GREEN}https://github.com/megadose/ignorant{Fore.YELLOW} -----") # Bug
                print(f"[!] Checking dependencies ...")
                check_ignorant(args.phone)
                print(f"\n{Fore.YELLOW}----- Launching haveibeenzuckered.com api : {Fore.GREEN}https://haveibeenzuckered.com/{Fore.YELLOW} -----")
                leaked(args.phone)
                
                phonesanitarize = args.phone.replace("+", "")
                getwhatsappinfos(phonesanitarize)
                if args.phone[3] == '0':
                    phone_format = args.phone[:3] + args.phone[4:]
                else:
                    phone_format = args.phone
                    
                getscamtel(phone_format)
                
                next_action = input(f"\n{Fore.YELLOW}[!] {Fore.RED}Exploiting Lydia misconfiguration may notify the user anonymously. Do you want to proceed ? {Fore.YELLOW}(y/n) : {Fore.GREEN}")
                if next_action.lower() == "y":  
                    proceed(phone_format)
                else:
                    print(f"{Fore.YELLOW}[!] Skipping Lydia checks...")
                
                
                print(f"\n{Fore.YELLOW}----- Launching searchX research -----")
                init_search(args.phone, "phone")
                
                print(f"\n{Fore.YELLOW}----- Launching breachvip research -----")
                breachvip_init(args.phone[3:], "Phone")

                # VF sorry les gars
                if args.phone.startswith("+33"):
                    reste = args.phone[3:]
                    if not reste.startswith("0"):
                        leakcheck_format = "0" + reste
                    else:
                        leakcheck_format = reste
                elif not args.phone.startswith("0"):
                    leakcheck_format = "0" + args.phone
                leackcheck(leakcheck_format)
                
                # VF sorry les gars
                if "+33" in args.phone:
                    reste = args.phone[3:]
                    if reste.startswith("0"):
                        reste = reste[1:]  
                    cybernews_format = "33" + reste
                init_cybernews(cybernews_format, "phone")
                
            except KeyboardInterrupt:
                print(f"\n{Fore.RED}[!] KeyboardInterrupt...\n{Fore.YELLOW}[!] End of search")
                sys.exit(0)
                
            
        if args.ip:
            try:
                torrents(args.ip) 
                ipinfo(args.ip)
                shodanit(args.ip)
                check_ip_with_virustotal(args.ip, 'Tokens/virustotal_token.txt')
                leakXx(args.ip)
                getwatweb(args.ip)
                
                # WHOIS
                print(f"\n{Fore.YELLOW}[!] whois search")
                print(f"{Fore.GREEN}[+] {Fore.YELLOW}Short output")
                try:
                    response = whois.whois(args.ip)
                    
                    for key, value in response.items():
                        print(f"{Fore.YELLOW}{key} : {Fore.GREEN}{value}")
                    
                    if hasattr(response, "text"):
                        print(f"\n{Fore.GREEN}[+] {Fore.YELLOW}Large output aviable{Fore.GREEN}")
                        print(response.text)

                    print(f"\n{Fore.YELLOW}----- Launching breachvip research -----")
                    print(f"[!] Trying IP search ...")
                    breachvip_init(args.ip, "IP")
                    print(f"[!] Trying Domain search ...")
                    breachvip_init(args.ip, "Domain")

                except Exception as e:
                    print(f"\n{Fore.RED}[!] Error : {e}")

                print(f"{Fore.YELLOW}--------------------------------------------------")
    
                print(f"\n{Fore.YELLOW}[!] Urls to visit")
                print(f"{Fore.YELLOW}--> {Fore.GREEN}https://vxintelligence.com/")

            except KeyboardInterrupt:
                print(f"\n{Fore.RED}[!] KeyboardInterrupt...\n{Fore.YELLOW}[!] End of search")
                sys.exit(0)
            
            
        if args.subdomain:
            try:
                subreponse(args.subdomain, 'Tokens/virustotal_token.txt')
                getwatweb(args.subdomain)
            
            except KeyboardInterrupt:
                print(f"\n{Fore.RED}[!] KeyboardInterrupt...\n{Fore.YELLOW}[!] End of search")
                sys.exit(0)
            
        if args.version:
            print(f"\n{Fore.YELLOW}[!] Wappalyzer search")
            if not args.version.startswith(('http://', 'https://')):
                args.version = 'https://' + args.version
            
            results = analyze(
                url=args.version,
                scan_type='full',  # 'fast', 'balanced', or 'full'
                threads=3
            )
            for url, techs in results.items():
                if not techs:
                    print(f"{Fore.MAGENTA}[-] No technologies found")
                    continue
                   
                for tech_name, details in techs.items():
                    version = details.get("version", "")
                    confidence = details.get("confidence", 0)
                    categories = details.get("categories", [])
                    groups = details.get("groups", [])

                    if version and version != "":
                        version_display = f"{Fore.RED}{version}"
                    else:
                        version_display = f"{Fore.GREEN}/"

                    print(f"{Fore.GREEN}[+] {Fore.YELLOW}Technology : {Fore.GREEN}{tech_name}")
                    print(f"    {Fore.YELLOW}Version    : {version_display}")
                    print(f"    {Fore.YELLOW}Confidence : {Fore.GREEN}{confidence}%")
                    print(f"    {Fore.YELLOW}Categories : {Fore.GREEN}{', '.join(categories) if categories else 'none'}")
                    print(f"    {Fore.YELLOW}Groups     : {Fore.GREEN}{', '.join(groups) if groups else 'none'}")
                    print("")          
            
            
        search_term, cve, port = None, None, None
        if args.exploit is not None:
            try:
                print(f"{Fore.YELLOW}----- Exploitdb from : {Fore.GREEN}https://www.exploit-db.com/{Fore.YELLOW} -----{Fore.GREEN}")
                if len(args.exploit) > 0:
                    search_term = args.exploit[0]
                if len(args.exploit) > 1:
                    cve = args.exploit[1]
                if len(args.exploit) > 2:
                    port = args.exploit[2]

                initexploitdb(search_term, cve, port)
                
            except KeyboardInterrupt:
                print(f"\n{Fore.RED}[!] KeyboardInterrupt...\n{Fore.YELLOW}[!] End of search")
                sys.exit(0)   

        if args.cve is not None:
            try:
                if len(args.cve) > 0:
                    search_term = args.cve[0]
                if len(args.cve) > 1:
                    cve = args.cve[1]
                
                searchcve(search_term, cve)
                
            except KeyboardInterrupt:
                print(f"\n{Fore.RED}[!] KeyboardInterrupt...\n{Fore.YELLOW}[!] End of search")
                sys.exit(0)  
    
                
        if args.dorks:
            try:
                initialize_dorksdb()
                dorksearch(args.dorks)
                
            except KeyboardInterrupt:
                print(f"\n{Fore.RED}[!] KeyboardInterrupt...\n{Fore.YELLOW}[!] End of search")
                sys.exit(0)
        
        
            
        # Filters management
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



        if args.root:
            if args.keywords or args.strict or args.regex:
                print(f"{Fore.YELLOW}[!] Directory search for :")
                
                if args.keywords:
                    print(f"    {Fore.GREEN}[+] {Fore.RED}{args.keywords} {Fore.GREEN}keyword(s)")
                
                if args.strict:
                    print(f"    {Fore.GREEN}[+] {Fore.RED}{args.strict} {Fore.GREEN}stric keyword(s)")
                
                if args.regex:
                    print(f"    {Fore.GREEN}[+] {Fore.RED}{args.regex} {Fore.GREEN}regex")
                
            
            print("")
            print(Fore.YELLOW + args.root) # Folder search -r
            
            
            
            if args.threads:
                walk_through_directories(args.root, keywords=keywords, num_threads=args.threads, very_verbose=very_verbose, verbose=args.verbose, ignored_extensions=ignored_extensions)
            else:
                start_time = time.time()
                
                if not (args.keywords or args.strict or args.regex):
                    print_tree(args.root, pbar=None, keywords=keywords, regex=args.regex, strict=args.strict, folders_only=args.folders_only, files_only=args.files_only, verbose=args.verbose, ignored_extensions=ignored_extensions, very_verbose=very_verbose, folders_verbose=args.folders_verbose)
                else:    
                    all_files = collect_files(args.root, ignored_extensions)
                    with initialize_progress_bar(len(all_files)) as pbar:
                        print_tree(args.root, pbar, keywords=keywords, regex=args.regex, strict=args.strict, folders_only=args.folders_only, files_only=args.files_only, verbose=args.verbose, ignored_extensions=ignored_extensions, very_verbose=very_verbose, folders_verbose=args.folders_verbose)
                print("")
                elapsed_time = time.time() - start_time
                formatted_time = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))
                print(f"{Fore.YELLOW}[!] Elapsed time : {Fore.GREEN}{formatted_time} ({elapsed_time:.2f} seconds)")
                
        if args.rootfile:
            if args.threads:
                print(f"{Fore.RED}[!] --threads args detected ... Launching normal mode for -rf")
            if args.keywords or args.strict or args.regex:
                print(f"{Fore.YELLOW}[!] File search for :")
                
                if args.keywords:
                    print(f"    {Fore.GREEN}[+] {Fore.RED}{args.keywords} {Fore.GREEN}keyword(s)")
                
                if args.strict:
                    print(f"    {Fore.GREEN}[+] {Fore.RED}{args.strict} {Fore.GREEN}stric keyword(s)")
                
                if args.regex:
                    print(f"    {Fore.GREEN}[+] {Fore.RED}{args.regex} {Fore.GREEN}regex")
                
            print("")        
            print(Fore.YELLOW + args.rootfile) # File search -r
            start_time = time.time()
            #total_lines = count_lines_in_file(args.rootfile)
            #with initialize_progress_bar(total_lines) as pbar:
            print_tree("file!" + args.rootfile, keywords=keywords, regex=args.regex, strict=args.strict, folders_only=args.folders_only, files_only=args.files_only, verbose=args.verbose, ignored_extensions=ignored_extensions, very_verbose=very_verbose, folders_verbose=args.folders_verbose)
            print("")
            elapsed_time = time.time() - start_time
            formatted_time = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))
            print(f"{Fore.YELLOW}[!] Elapsed time : {Fore.GREEN}{formatted_time} ({elapsed_time:.2f} seconds)")
                
        if output_file:
            sys.stdout.close()
            

        print(f"\n{Fore.YELLOW}[!] End of search")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] KeyboardInterrupt...\n{Fore.YELLOW}[!] End of search")
        sys.exit(0)
        
if __name__ == "__main__":
    main()
