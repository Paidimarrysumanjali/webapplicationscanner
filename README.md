# Web Application Vulnerability Scanner

A simple **Web Vulnerability Scanner** built with **Python** and **Flask**.  
It scans target websites for common security issues such as:

- Cross-Site Scripting (XSS)  
- SQL Injection (SQLi)  
- Cross-Site Request Forgery (CSRF)  
- Open Redirect  
- Command Injection (basic detection)

---

## What This Project Does

This tool crawls the target website, identifies forms and links, and tests them using common attack payloads.  
It checks whether the target is vulnerable by looking for the payload reflected in the responses or errors.  

The results are displayed in a user-friendly web interface showing:

- Vulnerability type  
- URL where vulnerability was found  
- Severity (High, Medium, Low)  
- Evidence (payload used or message)  
- Description of the risk  

---

## How to Use This Project

### Step 1: Clone the Repository

Open your terminal (or VS Code terminal) and run:

```bash
git clone https://github.com/Paidimarrysumanjali/webapplicationscanner.git
cd webapplicationscanner
