# SearchX

![Main menu](https://github.com/raphaelthief/SearchX/blob/main/Pictures/Main1.JPG "Main menu")

## Disclaimer :

The user acknowledges and expressly agrees that the use of this tool is entirely at their own risk.
The user is solely responsible for the use they make of this tool. It is understood that this tool is intended to facilitate research and access to information in large databases and must not be used for illegal, malicious, or unethical purposes.

## Usage :

SearchX aims to accurately extract specific keywords from a wide range of folders and files. In the context of a penetration test (pentest), it can be used to find certain keywords within a large database.

For example: you may search for access logs related to a domain name "@company.com" or user login credentials with a combination such as "user", "password", "credential", "secret", etc.


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

