# SearchX

![Main menu](https://github.com/raphaelthief/SearchX/blob/main/Pictures/Main1.JPG "Main menu")

## Disclaimer :

The user acknowledges and expressly agrees that the use of this tool is entirely at their own risk.
The user is solely responsible for the use they make of this tool. It is understood that this tool is intended to facilitate research and access to information in large databases and must not be used for illegal, malicious, or unethical purposes.

## Usage :

SearchX is a Python-based script designed for keyword searches, data analysis, and penetration testing tasks within large databases, directories, or specific files. It supports various data formats and search methods, making it highly versatile for cybersecurity, OSINT, and investigative purposes.


## Key Features :

### Search Capabilities :
- Directory and file search with keyword matching (-k), regex patterns (-x), and strict keyword matching (-kx).
- Supports verbose (-v) and very verbose (-vv) output modes for detailed context.

### Specialized Search Functions :
- Email analysis : Using tools like Holehe and Ghunt to search email-related data.
- Username lookup : Integrates with Blackbird and GitHub tools.
- IP analysis : Provides information through APIs such as Shodan and VirusTotal.
- Password breach checks : Verifies passwords against breached databases.
- Exploit and CVE search : Retrieves vulnerabilities from exploit-db and CVE databases.
- Phone number lookup : Uses APIs and phone number information libraries.

### Filters :
- Exclude specific file types (-e) or ignore default extensions like .jpg, .zip (-i).
- Focus searches on directories (-d) or files only (-f).

### Advanced Utilities :
- Integration with Google Dorking (--dorks) for enhanced search capabilities.
- Subdomain enumeration using LeakIX and WhatWeb, ...
- Search through the COMB (Compilation of Many Breaches) database.
- Logging output to a file (-o) with ANSI color removal for easier reading.

### Update Mechanism :
- Automatically pulls updates from the GitHub repository (--update).

### Usability :
- Displays banners with usage information.
- Provides examples through --usage for user guidance.
- Compatible with Windows and Linux environments.

### And more :
- Github dorks, skype, and much more ...

## Help menu : 

![Help menu](https://github.com/raphaelthief/SearchX/blob/main/Pictures/Help1.JPG "Help menu")

## Usages menu : 

![Usages menu](https://github.com/raphaelthief/SearchX/blob/main/Pictures/Usages.JPG "Usages menu")

## Exemples : 

```
python searchX.py -r <Directory path>
```
![Root](https://github.com/raphaelthief/SearchX/blob/main/Pictures/Root.JPG "Root")

```
python searchX.py -r <Directory path> -k test,update -vv
```
![Root](https://github.com/raphaelthief/SearchX/blob/main/Pictures/Exemple1.JPG "Root")

```
python searchX.py -r <Directory path> -k test,update -dv -v
```
![Root](https://github.com/raphaelthief/SearchX/blob/main/Pictures/Exemple2.JPG "Root")

```
python searchX.py --comb <keyword>
```
![Root](https://github.com/raphaelthief/SearchX/blob/main/Pictures/proxynova.JPG "proxynova")

