import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from flask import Flask, request, render_template, redirect, url_for
import logging
import os

app = Flask(__name__)

# Setup logging
if not os.path.exists('logs'):
    os.makedirs('logs')
logging.basicConfig(filename='logs/vulnerabilities.log', level=logging.INFO)

# Global scan results
scan_results = []

# Payloads
XSS_PAYLOADS = ["<script>alert('XSS')</script>", "'><script>alert(1)</script>"]
SQLI_PAYLOADS = ["' OR 1=1--", "'; DROP TABLE users; --"]
CMDI_PAYLOADS = ["; ls", "&& whoami"]
REDIRECT_PAYLOADS = ["//evil.com"]

HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

def log_vulnerability(url, vuln_type, evidence, severity, description):
    logging.info(f"{vuln_type} | {url} | {evidence} | {severity}")
    scan_results.append({
        "url": url,
        "type": vuln_type,
        "evidence": evidence,
        "severity": severity,
        "description": description
    })

def is_error_in_response(resp_text):
    errors = [
        "you have an error in your sql syntax",
        "mysql_fetch",
        "ORA-01756",
        "unterminated string",
        "command not found"
    ]
    return any(err in resp_text.lower() for err in errors)

def crawl_and_scan(url):
    global scan_results
    scan_results.clear()

    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        links = soup.find_all("a", href=True)

        # Form testing
        for form in forms:
            action = form.get("action") or ""
            method = form.get("method", "get").lower()
            form_url = urljoin(url, action)
            inputs = form.find_all("input")
            form_data = {inp.get("name"): "test" for inp in inputs if inp.get("name")}

            for payload in XSS_PAYLOADS + SQLI_PAYLOADS + CMDI_PAYLOADS:
                for key in form_data:
                    form_data[key] = payload

                if method == "post":
                    resp = requests.post(form_url, data=form_data, headers=HEADERS)
                else:
                    resp = requests.get(form_url, params=form_data, headers=HEADERS)

                if payload in resp.text:
                    vuln_type = "XSS" if payload in XSS_PAYLOADS else "Command Injection" if payload in CMDI_PAYLOADS else "SQL Injection"
                    description = {
                        "XSS": "Reflected input found in response. Could lead to session theft.",
                        "SQL Injection": "SQL error detected. Query might be injectable.",
                        "Command Injection": "Command injection string reflected. Risk of code execution."
                    }[vuln_type]
                    log_vulnerability(form_url, vuln_type, payload, "High", description)

                elif is_error_in_response(resp.text):
                    log_vulnerability(form_url, "SQL Injection", "Error message in response", "High", "SQL error patterns detected.")

            # CSRF check
            if not any(re.search("csrf", (inp.get("name") or ""), re.I) for inp in inputs):
                log_vulnerability(form_url, "CSRF", "CSRF token missing", "Medium", "No CSRF token found in form.")

        # Open Redirect check
        for a in links:
            href = a.get("href")
            if any(payload in href for payload in REDIRECT_PAYLOADS):
                redir_url = urljoin(url, href)
                log_vulnerability(redir_url, "Open Redirect", href, "Low", "Open redirect detected in URL.")

    except Exception as e:
        logging.error(f"Error scanning {url}: {e}")

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url")
        crawl_and_scan(url)
        return redirect(url_for("results"))
    return render_template("index.html")

@app.route("/results")
def results():
    return render_template("results.html", results=scan_results)

if __name__ == "__main__":
    app.run(debug=True)
