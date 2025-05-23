import requests, socket, argparse, re, os
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import Fore, Style

def banner():
    print(Fore.CYAN + r"""
 __     ___       _       ____                                      
 \ \   / (_) __ _| |__   |  _ \ _ __ _____  ___   _ __  _   ___  __ 
  \ \ / /| |/ _` | '_ \  | |_) | '__/ _ \ \/ / | | '_ \| | | \ \/ / 
   \ V / | | (_| | | | | |  __/| | | (_) >  <| |_| | | | |_| |>  <  
    \_/  |_|\__, |_| |_| |_|   |_|  \___/_/\_\\__,_| |_|\__,_/_/\_\ 
             |___/              Lightweight Penetration Testing Tool
    """ + Style.RESET_ALL)

def port_scan(ip):
    print(Fore.YELLOW + "[*] Starting port scan..." + Style.RESET_ALL)
    common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 8080]
    for port in common_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        if s.connect_ex((ip, port)) == 0:
            print(Fore.GREEN + f"[+] Port {port} is open." + Style.RESET_ALL)
        s.close()

def http_headers_analysis(url):
    print(Fore.YELLOW + "[*] Analyzing HTTP headers..." + Style.RESET_ALL)
    try:
        response = requests.get(url)
        headers = response.headers
        missing = []
        for h in ['Content-Security-Policy', 'X-Frame-Options', 'X-XSS-Protection', 'Strict-Transport-Security']:
            if h not in headers:
                missing.append(h)
        if missing:
            print(Fore.RED + f"[-] Missing security headers: {', '.join(missing)}" + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "[+] All essential headers are present." + Style.RESET_ALL)
    except:
        print(Fore.RED + "[-] Failed to retrieve headers." + Style.RESET_ALL)

def directory_brute_force(url):
    print(Fore.YELLOW + "[*] Starting directory brute force..." + Style.RESET_ALL)
    wordlist = "wordlists/common.txt"
    if not os.path.exists(wordlist):
        print(Fore.RED + "[-] Wordlist not found." + Style.RESET_ALL)
        return
    with open(wordlist) as f:
        paths = f.read().splitlines()
    for path in paths:
        full_url = urljoin(url, path)
        r = requests.get(full_url)
        if r.status_code == 200:
            print(Fore.GREEN + f"[+] Found: {full_url}" + Style.RESET_ALL)

def simple_sqli_xss_test(url):
    print(Fore.YELLOW + "[*] Running simple SQLi/XSS tests..." + Style.RESET_ALL)
    payloads = ["' OR '1'='1", "<script>alert(1)</script>"]
    for payload in payloads:
        r = requests.get(url, params={"q": payload})
        if payload in r.text:
            print(Fore.RED + f"[!] Potential vulnerability found with payload: {payload}" + Style.RESET_ALL)

if __name__ == "__main__":
    banner()
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', help="Target URL (e.g. http://example.com)", required=True)
    parser.add_argument('--scan', help="Scan type: all, ports, headers, dirs, payloads", default="all")
    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.target.split("//")[-1].split("/")[0])
    except:
        ip = None

    if args.scan in ['all', 'ports'] and ip:
        port_scan(ip)
    if args.scan in ['all', 'headers']:
        http_headers_analysis(args.target)
    if args.scan in ['all', 'dirs']:
        directory_brute_force(args.target)
    if args.scan in ['all', 'payloads']:
        simple_sqli_xss_test(args.target)






#wordlist
admin
login
dashboard
config
robots.txt
backup
uploads




#installation
pip install -r requirements.txt





#EXAMPLE COMMAND
python scanner.py --target http://testphp.vulnweb.com --scan all





#EXAMPLE OUTPUT.
 __     ___       _       ____                                      
 \ \   / (_) __ _| |__   |  _ \ _ __ _____  ___   _ __  _   ___  __ 
  \ \ / /| |/ _` | '_ \  | |_) | '__/ _ \ \/ / | | '_ \| | | \ \/ / 
   \ V / | | (_| | | | | |  __/| | | (_) >  <| |_| | | | |_| |>  <  
    \_/  |_|\__, |_| |_| |_|   |_|  \___/_/\_\\__,_| |_|\__,_/_/\_\ 
             |___/              Lightweight Penetration Testing Tool

[*] Starting port scan...
[+] Port 80 is open.
[+] Port 443 is open.

[*] Analyzing HTTP headers...
[-] Missing security headers: Content-Security-Policy, Strict-Transport-Security

[*] Starting directory brute force...
[+] Found: http://testphp.vulnweb.com/admin
[+] Found: http://testphp.vulnweb.com/login
[+] Found: http://testphp.vulnweb.com/robots.txt

[*] Running simple SQLi/XSS tests...
[!] Potential vulnerability found with payload: ' OR '1'='1
