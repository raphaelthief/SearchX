import sqlite3
import folium
import os
import shutil
from glob import glob
from datetime import datetime
from colorama import init, Fore, Style

init()  # Init colorama for colored text in terminal

M = Fore.MAGENTA
G = Fore.GREEN
R = Fore.RED
C = Fore.CYAN
Y = Fore.YELLOW

def searchtarget(query_input):
    DB_PATH = r"wigle_db.sqlite"

    queries = [q.strip() for q in query_input.split(",") if q.strip()]

    if not queries:
        print(f"{R}Invalid entry")
        exit()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    placeholders = ",".join("?" for _ in queries)
    sql = f"""
        SELECT ssid, bssid, lastlat, lastlon, capabilities, lasttime
        FROM network
        WHERE ssid IN ({placeholders}) OR bssid IN ({placeholders})
    """
    cursor.execute(sql, queries + queries)
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        print(f"{M}[-] No data found")
        exit()

    print(f"{G}[+] {Y}{len(rows)} {C}networks found")

    locations = []
    for ssid, bssid, lat, lon, caps, lasttime in rows:
        try:
            lat_f = float(lat)
            lon_f = float(lon)
            locations.append((ssid, bssid, lat_f, lon_f, caps, lasttime))
        except (TypeError, ValueError):
            continue

    if not locations:
        print(f"{M}[-] No valid location found")
        exit()

    first_lat, first_lon = locations[0][2], locations[0][3]
    m = folium.Map(location=[first_lat, first_lon], zoom_start=15)

    for ssid, bssid, lat, lon, caps, lasttime in locations:
        popup_text = f"""
        <b>SSID:</b> {ssid}<br>
        <b>BSSID:</b> {bssid}<br>
        <b>Capabilities:</b> {caps}<br>
        <b>Last seen:</b> {lasttime}
        """
        folium.Marker(
            location=[lat, lon],
            popup=popup_text,
            icon=folium.Icon(color="blue", icon="wifi", prefix="fa")
        ).add_to(m)

    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_file = f"map_{now}.html"
    m.save(output_file)
    print(f"{G}[+] Map saved in {Y}{output_file}")
    
    
def merge_wifi_db():
    ROOT_DIR = os.getcwd()
    MERGE_DIR = os.path.join(ROOT_DIR, r"wigle_to_merge")
    OLD_DIR = os.path.join(ROOT_DIR, r"wigle_old")
    FINAL_DB = os.path.join(ROOT_DIR, r"wigle_db.sqlite")

    # 1️⃣ Créer wigle_to_merge si absent
    if not os.path.exists(MERGE_DIR):
        os.makedirs(MERGE_DIR)
        print(f"{R}No DB to merge (wigle_to_merge folder created)")
        exit()

    db_files = glob(os.path.join(MERGE_DIR, "*.sqlite"))
    if not db_files:
        print(f"{R}No DB to merge (wigle_to_merge folder is empty)")
        exit()

    if not os.path.exists(FINAL_DB):
        conn_final = sqlite3.connect(FINAL_DB)
        conn_final.close()
        print(f"{G}[+] Created final DB: {Y}{FINAL_DB}")

    conn_final = sqlite3.connect(FINAL_DB)
    cursor_final = conn_final.cursor()

    unique_columns = {
        "network": ["bssid"],
        "location": ["lat", "lon", "time"],
        "route": ["run_id", "time"],
        "android_metadata": ["locale"]
    }

    for db_file in db_files:
        print(f"{G}[+] Merging {Y}{db_file} ...")
        conn_temp = sqlite3.connect(db_file)
        cursor_temp = conn_temp.cursor()

        cursor_temp.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor_temp.fetchall() if not row[0].startswith('sqlite_')]

        for table in tables:
            # Créer la table finale si elle n'existe pas
            cursor_temp.execute(f"PRAGMA table_info({table})")
            columns = [col[1] for col in cursor_temp.fetchall()]

            if not columns:
                continue 

            col_defs = ", ".join(f"{col} TEXT" for col in columns)
            cursor_final.execute(f"CREATE TABLE IF NOT EXISTS {table} ({col_defs})")

            if table in unique_columns:
                idx_name = f"idx_unique_{table}"
                cols_idx_exist = [col for col in unique_columns[table] if col in columns]
                if cols_idx_exist:
                    cols_idx_str = ", ".join(cols_idx_exist)
                    cursor_final.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS {idx_name} ON {table} ({cols_idx_str})")

            rows = cursor_temp.execute(f"SELECT * FROM {table}").fetchall()
            if not rows:
                continue

            cols_str = ", ".join(columns)
            placeholders = ", ".join("?" for _ in columns)
            cursor_final.executemany(
                f"INSERT OR IGNORE INTO {table} ({cols_str}) VALUES ({placeholders})", rows
            )

        conn_temp.close()

    conn_final.commit()
    conn_final.close()

    if not os.path.exists(OLD_DIR):
        os.makedirs(OLD_DIR)

    for db_file in db_files:
        shutil.move(db_file, OLD_DIR)

    print(f"{G}[+] Merging complete. Moved {len(db_files)} DBs to wigle_old")