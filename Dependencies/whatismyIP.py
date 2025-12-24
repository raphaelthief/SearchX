import requests
from datetime import datetime

# colorama
from colorama import init, Fore, Style
init() 

def format_date(date_str):
    try:
        return datetime.fromisoformat(date_str.replace("Z", "")).date()
    except Exception:
        return date_str

def whatismyipAPI_DB(email):
    URL = "https://api.whatismyip.com/app.php"

    headers = {
        "Accept": "*/*",
        "Accept-Language": "fr-FR,fr;q=0.8",
        "Origin": "https://www.whatismyip.com",
        "Referer": "https://www.whatismyip.com/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "Sec-GPC": "1",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/143.0.0.0 Safari/537.36"
        ),
    }

    files = {
        "action": (None, "data-breach-check"),
        "email": (None, email),
    }

    response = requests.post(URL, headers=headers, files=files, timeout=15)
    response.raise_for_status()

    breaches = response.json()

    # --- API error handling ---
    if isinstance(breaches, dict) and "error" in breaches:
        error_msg = breaches["error"]

        if "lookup limit has been reached" in error_msg.lower():
            print(Fore.RED + Style.BRIGHT + "🚫 API RATE LIMIT REACHED")
            print(Fore.YELLOW + "This API is rate-limited based on your IP address.")
            print(Fore.YELLOW + "➡️ Use Tor, a VPN or a proxy")
            return

        print(Fore.RED + f"❌ API Error: {error_msg}")
        return
    # ---------------------------

    # Normalize response
    if isinstance(breaches, dict):
        breaches = [breaches]
    elif isinstance(breaches, str):
        print(Fore.CYAN + f"ℹ️ API Response: {breaches}")
        return

    print(
        Fore.CYAN
        + Style.BRIGHT
        + f"\n🔐 Data breaches found : {len(breaches)}"
    )

    for i, b in enumerate(breaches, 1):
        print(Fore.BLUE + "=" * 70)
        print(
            Style.BRIGHT
            + Fore.WHITE
            + f"[{i}] {b.get('Title', 'N/A')}"
        )
        print(Fore.BLUE + "-" * 70)

        print(
            Fore.GREEN
            + f"📅 Breach date      : {format_date(b.get('BreachDate'))}"
        )
        print(
            Fore.GREEN
            + f"🌐 Domain           : {b.get('Domain') or '—'}"
        )
        print(
            Fore.GREEN
            + f"👥 Accounts exposed : {b.get('PwnCount'):,}"
        )
        print(
            Fore.GREEN
            + f"✔  Verified         : {'Yes' if b.get('IsVerified') else 'No'}"
        )

        data_classes = ", ".join(b.get("DataClasses", []))
        print(
            Fore.MAGENTA
            + f"📦 Exposed data     : {data_classes}"
        )
    print(Fore.BLUE + "=" * 70 + "\n")
