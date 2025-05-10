import requests
import time
import re
from colorama import Fore, Style, init

init(autoreset=True)

VT_API_KEY = "a85b51e77018cad36a62d5eb77e640106cb7c5882b7df119c4101d326a8fa22a"  # Replace with your API key

def print_banner():
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
████████╗     ███████╗ ██████╗  █████╗ ███╗   ██╗
╚══██╔══╝     ██╔════╝██╔════╝ ██╔══██╗████╗  ██║
   ██║█████╗  ███████╗██║  ███╗███████║██╔██╗ ██║
   ██║╚════╝  ╚════██║██║   ██║██╔══██║██║╚██╗██║
   ██║        ███████║╚██████╔╝██║  ██║██║ ╚████║
   ╚═╝        ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝

{Style.RESET_ALL}
{Fore.YELLOW}  🔍 Lightweight Threat Intelligence Scanner
  👨‍💻 Developed by: {Fore.GREEN}Abhay Patel
  📁 Output saved to: {Fore.MAGENTA}output_report.txt
"""
    print(banner)

def draw_terminal_pie_chart(malicious, harmless, suspicious):
    total = malicious + harmless + suspicious
    malicious_percent = (malicious / total) * 100 if total else 0
    harmless_percent = (harmless / total) * 100 if total else 0
    suspicious_percent = (suspicious / total) * 100 if total else 0

    # Create a simple text-based pie chart
    print(Fore.CYAN + "\n[+] Scan Result Breakdown:")

    chart = {
        'Malicious': malicious_percent,
        'Harmless': harmless_percent,
        'Suspicious': suspicious_percent
    }

    for label, percent in chart.items():
        bar = '█' * int(percent // 2)  # Scale to fit terminal width
        print(f"{Fore.RED if label == 'Malicious' else Fore.GREEN if label == 'Harmless' else Fore.YELLOW}{label}: {bar} {percent:.1f}%")

def is_suspicious_email(email):
    free_domains = ['mailinator.com', 'tempmail.com', 'guerrillamail.com']
    phishing_keywords = ['secure', 'update', 'verify', 'account', 'bank', 'login']
    domain = email.split('@')[-1].lower()
    local = email.split('@')[0].lower()

    if any(word in local for word in phishing_keywords):
        return True
    if domain in free_domains or re.match(r'.*\.tk$', domain):
        return True
    if re.search(r'(0|1|3|5|7|9)', domain):  # zero-day typo indicator
        return True
    return False

def is_ip_address(input_str):
    # Validate if input is a valid IPv4 address
    return bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", input_str))

def scan_input(user_input):
    headers = {"x-apikey": VT_API_KEY}
    output = []

    if "@" in user_input and "." in user_input:
        print(Fore.BLUE + "[*] Checking email address pattern...")
        if is_suspicious_email(user_input):
            print(Fore.RED + "🚨 Warning: This email address looks suspicious or phishing-related!")
            output.append(f"Email check: {user_input} -> Suspicious\n")
        else:
            print(Fore.GREEN + "✔️ This email address looks normal.")
            output.append(f"Email check: {user_input} -> Normal\n")
        return

    elif is_ip_address(user_input):
        print(Fore.BLUE + "[*] Scanning IP address...")
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{user_input}"
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            scan_type = "IP Address"
        else:
            print(Fore.RED + "[!] Error fetching IP address info.")
            return

    elif "." in user_input or user_input.startswith("http"):
        print(Fore.BLUE + "[*] Scanning URL...")
        url = "https://www.virustotal.com/api/v3/urls"
        data = {"url": user_input}
        response = requests.post(url, headers=headers, data=data)

        if response.status_code == 200:
            scan_id = response.json()["data"]["id"]
            time.sleep(3)
            result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers)
            stats = result.json()["data"]["attributes"]["stats"]
            categories = result.json()["data"]["attributes"].get("categories", {})
            scan_type = "URL"

            if any("phish" in v.lower() for v in categories.values()):
                print(Fore.RED + "🚨 Warning: This URL is categorized as phishing!")
                output.append("Phishing Category Detected!\n")
        else:
            print(Fore.RED + "[!] Error scanning URL.")
            return

    else:
        print(Fore.BLUE + "[*] Scanning file hash...")
        url = f"https://www.virustotal.com/api/v3/files/{user_input}"
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            scan_type = "Hash"
        else:
            print(Fore.RED + "[!] Error fetching hash info.")
            return

    malicious = stats.get("malicious", 0)
    harmless = stats.get("harmless", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())

    print(Fore.YELLOW + f"\n🔎 {scan_type} Scan Results for: {Fore.CYAN}{user_input}")
    print(f"{Fore.RED}- Malicious     : {malicious}")
    print(f"{Fore.GREEN}- Harmless      : {harmless}")
    print(f"{Fore.YELLOW}- Suspicious    : {suspicious}")
    print(f"{Fore.WHITE}- Total Engines : {total}")
    percent = (malicious / total) * 100 if total else 0
    print(f"{Fore.MAGENTA}- Malicious %   : {percent:.1f}%")

    # Threat Level
    if percent <= 10:
        threat_level = "Low"
        level_color = Fore.GREEN
        symbol = "✅"
    elif percent <= 40:
        threat_level = "Medium"
        level_color = Fore.YELLOW
        symbol = "⚠️"
    else:
        threat_level = "High"
        level_color = Fore.RED
        symbol = "🚨"

    print(f"{level_color}- Threat Level  : {symbol} {threat_level}")
    output.append(f"Scan input: {user_input}")
    output.append(f"Type: {scan_type}")
    output.append(f"Malicious: {malicious}")
    output.append(f"Harmless: {harmless}")
    output.append(f"Suspicious: {suspicious}")
    output.append(f"Total Engines: {total}")
    output.append(f"Malicious %: {percent:.1f}%")
    output.append(f"Threat Level: {threat_level}")
    output.append("-" * 40)

    with open("output_report.txt", "a") as f:
        f.write("\n".join(output) + "\n\n")

    if total > 0:
        draw_terminal_pie_chart(malicious, harmless, suspicious)

def main():
    print_banner()
    while True:
        user_input = input(Fore.CYAN + "🔗 T-SCAN > Enter target (or type 'exit' to quit): ").strip()
        if user_input.lower() == "exit":
            print(Fore.GREEN + "Exiting... Goodbye!")
            break
        elif user_input:
            scan_input(user_input)
        else:
            print(Fore.RED + "⚠️  No input provided. Please enter a URL, file hash, or email.")

if __name__ == "__main__":
    main()
