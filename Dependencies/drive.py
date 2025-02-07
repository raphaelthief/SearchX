# Credits to :
# Twitter : @MalfratsInd
# Github : https://github.com/Malfrats/xeuledoc

from datetime import datetime
from pathlib import Path
import json
import sys
import sys
import httpx

# colorama
from colorama import init, Fore, Style

init() # Init colorama

class TMPrinter():
    def __init__(self):
        self.max_len = 0

    def out(self, text):
        if len(text) > self.max_len:
            self.max_len = len(text)
        else:
            text += (" " * (self.max_len - len(text)))
        print(text, end='\r')
    def clear(self):
    	print(" " * self.max_len, end="\r")

def doc_hunt(doc_link, tmprinter):

    doc_id = ''.join([x for x in doc_link.split("?")[0].split("/") if len(x) in (33, 44)])
    if doc_id:
        print(f"\n{Fore.YELLOW}Document ID : {Fore.GREEN}{doc_id}\n")
    else:
        exit(f"\n{Fore.RED}Document ID not found.\nPlease make sure you have something that looks like this in your link :\1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms")


    headers = {"X-Origin": "https://drive.google.com"}
    client = httpx.Client(headers=headers)

    url = f"https://clients6.google.com/drive/v2beta/files/{doc_id}?fields=alternateLink%2CcopyRequiresWriterPermission%2CcreatedDate%2Cdescription%2CdriveId%2CfileSize%2CiconLink%2Cid%2Clabels(starred%2C%20trashed)%2ClastViewedByMeDate%2CmodifiedDate%2Cshared%2CteamDriveId%2CuserPermission(id%2Cname%2CemailAddress%2Cdomain%2Crole%2CadditionalRoles%2CphotoLink%2Ctype%2CwithLink)%2Cpermissions(id%2Cname%2CemailAddress%2Cdomain%2Crole%2CadditionalRoles%2CphotoLink%2Ctype%2CwithLink)%2Cparents(id)%2Ccapabilities(canMoveItemWithinDrive%2CcanMoveItemOutOfDrive%2CcanMoveItemOutOfTeamDrive%2CcanAddChildren%2CcanEdit%2CcanDownload%2CcanComment%2CcanMoveChildrenWithinDrive%2CcanRename%2CcanRemoveChildren%2CcanMoveItemIntoTeamDrive)%2Ckind&supportsTeamDrives=true&enforceSingleParent=true&key=AIzaSyC1eQ1xj69IdTMeii5r7brs3R90eck-m7k"

    retries = 100
    for retry in range(retries):
        req = client.get(url)
        if "File not found" in req.text:
            print(f"{Fore.RED}[-] This file does not exist or is not public")
        elif "rateLimitExceeded" in req.text:
            tmprinter.out(f"{Fore.RED}[-] Rate-limit detected, retrying... {retry+1}/{retries}")
            continue
        else:
            break
    else:
        tmprinter.clear()
        exit(f"{Fore.RED}[-] Rate-limit exceeded. Try again later.")

    tmprinter.clear()

    data = json.loads(req.text)
    # Extracting informations

    # Dates

    created_date = datetime.strptime(data["createdDate"], '%Y-%m-%dT%H:%M:%S.%fz')
    modified_date = datetime.strptime(data["modifiedDate"], '%Y-%m-%dT%H:%M:%S.%fz')

    print(f"{Fore.GREEN}[+] {Fore.YELLOW}Creation date  : {Fore.GREEN}{created_date.strftime('%Y/%m/%d %H:%M:%S')} (UTC)")
    print(f"{Fore.GREEN}[+] {Fore.YELLOW}Last edit date : {Fore.GREEN}{modified_date.strftime('%Y/%m/%d %H:%M:%S')} (UTC)")

    # Permissions

    user_permissions = []
    if data["userPermission"]:
        if data["userPermission"]["id"] == "me":
            user_permissions.append(data["userPermission"]["role"])
            if "additionalRoles" in data["userPermission"]:
                user_permissions += data["userPermission"]["additionalRoles"]

    public_permissions = []
    owner = None
    for permission in data["permissions"]:
        if permission["id"] in ["anyoneWithLink", "anyone"]:
            public_permissions.append(permission["role"])
            if "additionalRoles" in data["permissions"]:
                public_permissions += permission["additionalRoles"]
        elif permission["role"] == "owner":
            owner = permission

    print(f"\n{Fore.YELLOW}Public permissions :{Fore.GREEN}")
    for permission in public_permissions:
        print(f"- {permission}")

    if public_permissions != user_permissions:
        print(F"{Fore.GREEN}[+] {Fore.YELLOW}You have special permissions :{Fore.GREEN}")
        for permission in user_permissions:
            print(f"- {permission}")

    if owner:
        print(f"\n{Fore.GREEN}[+] {Fore.YELLOW}Owner found !\n")
        print(f"{Fore.YELLOW}Name      : {Fore.GREEN}{owner['name']}")
        print(f"{Fore.YELLOW}Email     : {Fore.GREEN}{owner['emailAddress']}")
        print(f"{Fore.YELLOW}Google ID : {Fore.GREEN}{owner['id']}")

def drivehunt(target):
    if len(target)>1:
        tmprinter = TMPrinter()
        doc_hunt(target, tmprinter)
    else:
        print(f"{Fore.RED}Please give the link to a Google resource.\nExample : -dh https://docs.google.com/spreadsheets/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms")