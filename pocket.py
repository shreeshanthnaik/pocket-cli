import os
import re
import json
import requests
import datetime
import wikipedia
import shutil
import subprocess

# === 🔑 CONFIG ===
WEATHER_API_KEY = "your_openweathermap_api_key"
GEMINI_API_KEY = "your_gemini_api_key"
LAB_PATH = os.path.expanduser("~/pocket-lab")
CONFIG_PATH = os.path.expanduser("~/.pocket-cli")
USER_FILE = os.path.join(CONFIG_PATH, "user.json")
POCKET_SCRIPT_URL = "https://raw.githubusercontent.com/shreeshanthnaik/pocket-cli/main/pocket.py"

# === 📁 Setup ===
os.makedirs(LAB_PATH, exist_ok=True)
os.makedirs(CONFIG_PATH, exist_ok=True)
for folder in ["scans", "brute", "dirs", "sqlmap"]:
    os.makedirs(os.path.join(LAB_PATH, folder), exist_ok=True)

# === 💬 Speak + Print ===
def speak(msg):
    print(f"🤖 Pocket: {msg}", flush=True)
    try:
        os.system(f'termux-tts-speak "{msg}" 2>/dev/null')  # Android
    except:
        os.system(f'espeak "{msg}" 2>/dev/null')  # Debian fallback

# === 🎙 Input
def takeCommand():
    return input("👤 You: ").strip().lower()

# === 👤 User Config
def get_user():
    if os.path.exists(USER_FILE):
        with open(USER_FILE) as f:
            return json.load(f)["name"]
    name = input("👤 Enter your name: ").strip()
    with open(USER_FILE, "w") as f:
        json.dump({"name": name}, f)
    return name

# === 🌦 Weather
def get_weather(city):
    url = f"http://api.openweathermap.org/data/2.5/weather?q={city}&appid={WEATHER_API_KEY}&units=metric"
    try:
        res = requests.get(url).json()
        if res.get("main"):
            temp = res["main"]["temp"]
            desc = res["weather"][0]["description"]
            speak(f"{city.capitalize()} is {desc}, {temp}°C")
        else:
            speak("City not found.")
    except:
        speak("Failed to fetch weather.")

# === 📚 Wikipedia
def wiki_info(topic):
    try:
        result = wikipedia.summary(topic, sentences=2)
        speak(result)
    except:
        speak("Couldn't find anything.")

# === 🌐 Gemini AI
def ask_gemini(prompt):
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel("gemini-pro")
        response = model.generate_content(prompt)
        speak(response.text)
    except:
        speak("Gemini AI failed or not installed.")

# === 💾 Save Output
def save_output(cmd, filepath):
    result = os.popen(cmd).read()
    with open(filepath, "w") as f:
        f.write(result)
    speak(f"Saved to {filepath}")

# === 🔍 Hacking Tools
def run_nmap(target):
    path = os.path.join(LAB_PATH, "scans", f"nmap-{target.replace('.', '_')}.txt")
    save_output(f"nmap -A {target}", path)

def run_hydra(target):
    path = os.path.join(LAB_PATH, "brute", f"hydra-{target.replace('.', '_')}.txt")
    save_output(f"hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} ftp", path)

def run_sqlmap(url):
    path = os.path.join(LAB_PATH, "sqlmap", f"sqlmap-{url.replace('/', '_')}.txt")
    save_output(f"sqlmap -u {url} --batch", path)

def run_dirb(url):
    path = os.path.join(LAB_PATH, "dirs", f"dirb-{url.replace('/', '_')}.txt")
    save_output(f"dirb {url}", path)

# === 📝 Notes
def save_note(msg):
    with open(os.path.join(LAB_PATH, "notes.txt"), "a") as f:
        f.write(f"{datetime.datetime.now()}: {msg}\n")
    speak("Note saved.")

def show_notes():
    path = os.path.join(LAB_PATH, "notes.txt")
    if os.path.exists(path):
        with open(path) as f:
            print(f.read())
    else:
        speak("No notes found.")

# === 🌐 IP Info
def ip_lookup(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        if res["status"] == "success":
            speak(f"{ip}: {res['org']} - {res['city']}, {res['country']} - {res['isp']}")
        else:
            speak("IP lookup failed.")
    except:
        speak("Error during lookup.")

# === 📰 Hacker News
def get_news():
    try:
        r = requests.get("https://hacker-news.firebaseio.com/v0/topstories.json")
        ids = r.json()[:5]
        speak("Top tech headlines:")
        for i in ids:
            item = requests.get(f"https://hacker-news.firebaseio.com/v0/item/{i}.json").json()
            print("📰", item.get("title", "No title"))
    except:
        speak("Couldn't fetch news.")

# === 🔄 Auto Update
def update_pocket():
    try:
        cmd = f"curl -s -o {os.path.join(CONFIG_PATH, 'pocket.py')} {POCKET_SCRIPT_URL}"
        os.system(cmd)
        speak("Updated Pocket CLI.")
    except:
        speak("Update failed.")

# === 🔬 Advanced Scanning
def scan_hotspot():
    try:
        ip_output = os.popen("ip a | grep inet").read()
        match = re.search(r"inet\s(192\.168\.\d+\.\d+)/\d+", ip_output)
        if not match:
            speak("Could not detect hotspot subnet.")
            return
        subnet = match.group(1).rsplit('.', 1)[0] + ".0/24"
        speak(f"Scanning {subnet}...")
        result = os.popen(f"nmap -sn {subnet}").read()
        hosts = re.findall(r"Nmap scan report for ([\d.]+)", result)
        if not hosts:
            speak("No devices found.")
        else:
            for host in hosts:
                print(f"📡 {host} is online — 👋 Hello!")
    except:
        speak("Hotspot scan failed.")

def scan_network():
    subnet = input("Enter subnet (e.g. 192.168.1.0/24): ")
    subprocess.run(["nmap", "-sn", subnet])

def port_scan():
    target = input("Target IP: ").strip()
    subprocess.run(["nmap", "-sS", "-Pn", target])

def banner_grab():
    target = input("Target IP: ").strip()
    subprocess.run(["nmap", "-sV", target])

# === 📶 Wi-Fi Scanner (No Root)
def wifi_scan():
    try:
        result = os.popen("termux-wifi-scaninfo").read()
        networks = json.loads(result)
        path = os.path.join(LAB_PATH, "wifi-scan.txt")
        with open(path, "w") as f:
            for net in networks:
                line = f"SSID: {net.get('ssid')} | BSSID: {net.get('bssid')} | Signal: {net.get('level')} dBm\n"
                f.write(line)
                print(line.strip())
        speak(f"Found {len(networks)} networks. Saved to wifi-scan.txt.")
    except Exception as e:
        speak("Wi-Fi scan failed. Make sure you granted location permission.")

# === 🧠 Simulated Wi-Fi Brute-force
def wifi_brute_sim():
    ssid = input("Target SSID: ").strip()
    wordlist = ["12345678", "password", "admin123", "iloveyou", "mypassword"]
    correct_pass = "admin123"  # Simulated correct password
    speak(f"Starting simulated brute-force on {ssid}...")
    for pwd in wordlist:
        print(f"Trying password: {pwd}")
        if pwd == correct_pass:
            speak(f"Password found: {pwd}")
            return
    speak("Password not found in wordlist.")

# === 📜 Help
def show_help():
    print("""
📦 Pocket CLI Commands:
  weather <city>         - Show weather
  wikipedia <topic>      - Wiki summary
  scan <ip>              - Nmap full scan
  brute <ip>             - Hydra brute-force
  sqltest <url>          - SQL injection test
  dirs <url>             - Dirb directory test
  ipinfo <ip>            - IP details
  ai <question>          - Ask Gemini AI
  news                   - Tech headlines
  note <text>            - Save a note
  show notes             - Show all notes
  scan hotspot           - Scan your hotspot
  scan my network        - Scan your LAN
  port scan              - Port scan a device
  grab banner            - Detect OS/services
  wifi scan              - List nearby Wi-Fi networks
  wifi brute             - Simulated Wi-Fi brute force (for demo only)
  whoami                 - Show your name
  update pocket          - Pull latest version
  help                   - Show this list
  exit / quit / bye      - Exit
""")

# === 🎬 MAIN LOOP
if __name__ == "__main__":
    name = get_user()
    speak(f"Welcome back, {name}!")

    while True:
        cmd = takeCommand()

        if cmd.startswith("weather"):
            get_weather(cmd.replace("weather", "").strip())

        elif cmd.startswith("wikipedia"):
            wiki_info(cmd.replace("wikipedia", "").strip())

        elif cmd == "scan hotspot":
            scan_hotspot()

        elif cmd == "scan my network":
            scan_network()

        elif cmd == "port scan":
            port_scan()

        elif cmd in ["grab banner", "os detect"]:
            banner_grab()

        elif cmd.startswith("scan "):
            run_nmap(cmd.replace("scan", "").strip())

        elif cmd.startswith("brute "):
            run_hydra(cmd.replace("brute", "").strip())

        elif cmd.startswith("sqltest "):
            run_sqlmap(cmd.replace("sqltest", "").strip())

        elif cmd.startswith("dirs "):
            run_dirb(cmd.replace("dirs", "").strip())

        elif cmd.startswith("note "):
            save_note(cmd.replace("note", "").strip())

        elif cmd == "show notes":
            show_notes()

        elif cmd.startswith("ipinfo "):
            ip_lookup(cmd.replace("ipinfo", "").strip())

        elif cmd.startswith("ai "):
            ask_gemini(cmd.replace("ai", "").strip())

        elif cmd == "news":
            get_news()

        elif cmd == "whoami":
            speak(f"You are {name}")

        elif cmd == "update pocket":
            update_pocket()

        elif cmd == "wifi scan":
            wifi_scan()

        elif cmd == "wifi brute":
            wifi_brute_sim()

        elif cmd == "help":
            show_help()

        elif cmd in ["exit", "quit", "bye"]:
            speak("Goodbye!")
            break

        else:
            speak("Unknown command. Type 'help'.")