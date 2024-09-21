# Most of the code comes from https://github.com/p1ngul1n0/blackbird

import os, subprocess, asyncio, aiohttp, json, sys, warnings, random
from colorama import init, Fore, Style
from bs4 import BeautifulSoup
init() # Init colorama



file = open('Dependencies\\remake_blackbird\\data.json')
searchData = json.load(file)

file1 = open('Dependencies\\remake_blackbird\\data1.json')
searchData1 = json.load(file1)

file2 = open('Dependencies\\remake_blackbird\\data2.json')
searchData2 = json.load(file2)


currentOs = sys.platform
path = os.path.dirname(__file__)
warnings.filterwarnings('ignore')

useragents = open('Dependencies\\remake_blackbird\\useragents.txt').read().splitlines()
proxy = None

async def findUsername(username, interfaceType, flag_csv=False):
    
    timeout = aiohttp.ClientTimeout(total=100)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        semaphore = asyncio.Semaphore(1)  # Limit the number of concurrent requests to 10
        tasks = []
        for u in searchData["sites"]:
            task = asyncio.ensure_future(makeRequest(session, u, username, interfaceType, semaphore))
            tasks.append(task)

        results = await asyncio.gather(*tasks)
 
    timeout = aiohttp.ClientTimeout(total=100)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        semaphore = asyncio.Semaphore(1)  # Limit the number of concurrent requests to 10
        tasks = []
        for u in searchData1["sites"]:
            task = asyncio.ensure_future(makeRequest(session, u, username, interfaceType, semaphore))
            tasks.append(task)

        results = await asyncio.gather(*tasks)
 
    timeout = aiohttp.ClientTimeout(total=100)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        semaphore = asyncio.Semaphore(1)  # Limit the number of concurrent requests to 10
        tasks = []
        for u in searchData2["sites"]:
            task = asyncio.ensure_future(makeRequest(session, u, username, interfaceType, semaphore))
            tasks.append(task)

        results = await asyncio.gather(*tasks)
    
    print("")

async def makeRequest(session, u, username, interfaceType, semaphore):
    
    try:
        url = u["url"].format(username=username)
        jsonBody = None
        useragent = random.choice(useragents)
        headers = {
            "User-Agent": useragent
        }
        metadata = []
        if 'headers' in u:
            headers.update(eval(u['headers']))
        if 'json' in u:
            jsonBody = u['json'].format(username=username)
            jsonBody = json.loads(jsonBody)
        try:
            async with session.request(u["method"], url, json=jsonBody,proxy=proxy, headers=headers, ssl=False, timeout=20) as response:
                responseContent = await response.text()
                if 'content-type' in response.headers and "application/json" in response.headers["Content-Type"]:
                    jsonData = await response.json()
                else:
                    soup = BeautifulSoup(responseContent, 'html.parser')

                if eval(u["valid"]):
                    print(f'{Fore.LIGHTGREEN_EX}    [+]\033[0m - #{u["id"]} {Fore.BLUE}{u["app"]}\033[0m {Fore.LIGHTGREEN_EX}account found\033[0m - {Fore.YELLOW}{url}\033[0m [{response.status} {response.reason}]\033[0m')
                   
                    if 'metadata' in u:
                        metadata = []
                        for d in u["metadata"]:
                            try:
                                value = eval(d['value']).strip('\t\r\n')
                                print(f"       |--{d['key']}: {value}")
                                #tree.create_node(f"   |--{d['key']}: {value}",66677,parent=6667)
                   
                                metadata.append({"type": d["type"], "key": d['key'], "value": value})
                            except Exception as e:
                                pass
                    return ({"id": u["id"], "app": u['app'], "url": url, "response-status": f"{response.status} {response.reason}", "status": "FOUND", "error-message": None, "metadata": metadata})
                else:
                    if interfaceType == 'CLI':
                       
                       return ({"id": u["id"], "app": u['app'], "url": url, "response-status": f"{response.status} {response.reason}", "status": "NOT FOUND", "error-message": None, "metadata": metadata})
        except Exception as e:
            #print(e)
            try:
                if interfaceType == 'CLI':
                    
                    return ({"id": u["id"], "app": u['app'], "url": url, "response-status": None, "status": "ERROR", "error-message": repr(e), "metadata": metadata})
            except Exception as e:
                #print(e)
                pass
    except Exception as e:
        #print(e)
        pass


def blackbirdZ(uname):
    print(f"{Fore.YELLOW}[!] Searching for : {Fore.GREEN}{uname}{Fore.YELLOW}\n")

    #try:
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    #except:
        #pass
    interfaceType = 'CLI'
    asyncio.run(findUsername(uname, interfaceType, None))