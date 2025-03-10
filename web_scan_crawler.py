import requests
from bs4 import BeautifulSoup
import os
from urllib.parse import urlparse

def check_security_headers(headers):
    security_headers = [
        'X-Content-Type-Options',
        'Strict-Transport-Security'
    ]
    missing_headers = [header for header in security_headers if header not in headers]
    return missing_headers

def check_forms(soup):
    forms = soup.find_all('form')
    insecure_forms = []
    for form in forms:
        if not form.get('method') or form['method'].upper() == 'GET':
            insecure_forms.append(form.get('action', 'N/A'))
    return insecure_forms

def crawl_and_scan(url, visited):
    if url in visited:
        return
    visited.add(url)
    
    try:
        response = requests.get(url)
        headers = response.headers
        soup = BeautifulSoup(response.text, 'html.parser')

        # Check for missing security headers
        missing_headers = check_security_headers(headers)
        
        # Check for insecure forms
        insecure_forms = check_forms(soup)

        return missing_headers, insecure_forms, soup.find_all('a', href=True)

    except Exception as e:
        print(f"Error scanning {url}: {e}")
        return None, None, []

def generate_report(url, report_data):
    report_lines = [f"Green Tick Technical Assessment\nVULNERABILITY SCAN REPORT FOR {url}:\n"]
    
    missing_headers, insecure_forms, links = report_data
    
    if missing_headers:
        report_lines.append("MISSING HTTP SECURITY HEADERS:")
        report_lines.extend(f"- {header}" for header in missing_headers)
    
    if insecure_forms:
        report_lines.append("FORM WITHOUT PROPER METHOD ATTRIBUTE:")
        report_lines.extend(f"- {form}" for form in insecure_forms)
    
    report_lines.append("\nLinks Found:")
    report_lines.extend(f"- {link['href']}" for link in links)

    # Extract the domain name for the report file name
    domain_name = urlparse(url).netloc.replace("www.", "")  # Remove 'www.' if present
    report_file = f'vulnerability_scan_report_{domain_name}.txt'
    
    with open(report_file, 'w') as f:
        f.write("\n".join(report_lines))
    
    print(f"Report generated: {os.path.abspath(report_file)}")
    
    # Print a summary of the findings
    print("\n--- Summary of Findings ---")
    if missing_headers:
        print(f"MISSING HTTP SECURITY HEADERS: {', '.join(missing_headers)}")
    if insecure_forms:
        print(f"FORM WITHOUT PROPER METHOD ATTRIBUTE: {', '.join(insecure_forms)}")
    if not missing_headers and not insecure_forms:
        print("No vulnerabilities found.")

def main():
    # Prompt the user for the URL to scan
    url = input("Please enter the website URL you want to scan (e.g., https://example.com): ")
    
    visited = set()
    report_data = crawl_and_scan(url, visited)
    
    if report_data:
        generate_report(url, report_data)

if __name__ == "__main__":
    main()