import sys
import os
import re
import json
import csv
import time
import random
import socket
import ssl
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from collections import deque
from typing import Dict, List, Tuple, Set, Optional, Any
import threading
import queue

# --------------------------- Safe Color Handling --------------------------
class SafeColors:
    """Safe color implementation that never throws errors"""
    RED = ''
    GREEN = ''
    YELLOW = ''
    CYAN = ''
    MAGENTA = ''
    WHITE = ''
    RESET = ''
    
    @staticmethod
    def init():
        """Try to enable colors, but never fail"""
        try:
            import colorama
            from colorama import Fore, Style, init
            init(autoreset=True)
            SafeColors.RED = Fore.RED
            SafeColors.GREEN = Fore.GREEN
            SafeColors.YELLOW = Fore.YELLOW
            SafeColors.CYAN = Fore.CYAN
            SafeColors.MAGENTA = Fore.MAGENTA
            SafeColors.WHITE = Fore.WHITE
            SafeColors.RESET = Style.RESET_ALL
        except:
            pass

SafeColors.init()

# --------------------------- Optional Imports ---------------------------
HAS_AIOHTTP = False
HAS_BS4 = False

try:
    import aiohttp
    import asyncio
    HAS_AIOHTTP = True
except ImportError:
    pass

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    pass

# --------------------------- Constants -----------------------------------
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
TIMEOUT = 10
MAX_RETRIES = 2
MAX_DEPTH = 3
RATE_LIMIT = 0.5

COMMON_DIRS = [
    "admin", "login", "wp-admin", "backup", "config", "sql",
    "phpmyadmin", "uploads", "api", "v1", "test", "dev"
]

SENSITIVE_FILES = [
    ".env", ".git/config", ".htaccess", ".htpasswd", "backup.zip",
    "config.php", "wp-config.php", "database.sql", "dump.sql",
    "robots.txt", "sitemap.xml", "crossdomain.xml"
]

SQL_PAYLOADS = [
    ("'", "error"), ("\"", "error"), ("' OR '1'='1", "boolean"),
    ("' OR '1'='2", "boolean"), ("1' AND 1=1--", "boolean"),
    ("1' AND 1=2--", "boolean")
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>alert(1)</script>",
    "<svg onload=alert(1)>"
]

OPEN_REDIRECT_PAYLOADS = [
    "//evil.com", "https://evil.com", "//google.com"
]

SSRF_PAYLOADS = [
    "http://127.0.0.1:80",
    "http://localhost/",
    "file:///etc/passwd"
]

SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_.*",
    r"MySQLSyntaxErrorException",
    r"PostgreSQL.*ERROR",
    r"ORA-[0-9]{5}",
    r"SQLServer",
    r"unclosed quotation mark"
]

WAF_HEADERS = ["x-sucuri", "cf-ray", "x-waf", "x-protected-by"]

# --------------------------- Helper Functions ---------------------------
def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip('/')

def get_domain(url: str) -> str:
    return urlparse(url).netloc

def is_same_domain(url1: str, url2: str) -> bool:
    return get_domain(url1) == get_domain(url2)

def is_valid_url(url: str) -> bool:
    regex = re.compile(
        r'^(?:http|ftp)s?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def extract_links_simple(html: str, base_url: str) -> Set[str]:
    """Extract links using regex (no BeautifulSoup)"""
    links = set()
    # Simple regex for href attributes
    pattern = re.compile(r'href=["\'](.*?)["\']', re.IGNORECASE)
    for match in pattern.finditer(html):
        href = match.group(1).strip()
        if not href or href.startswith('#') or href.startswith('javascript:'):
            continue
        absolute = urljoin(base_url, href)
        if absolute.startswith(('http://', 'https://')):
            links.add(absolute)
    return links

def extract_forms_simple(html: str, base_url: str) -> List[Dict]:
    """Extract forms using regex (no BeautifulSoup)"""
    forms = []
    # Find form tags
    form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
    for form_match in form_pattern.finditer(html):
        form_html = form_match.group(0)
        # Get action
        action_match = re.search(r'action=["\'](.*?)["\']', form_html, re.IGNORECASE)
        action = action_match.group(1) if action_match else ''
        # Get method
        method_match = re.search(r'method=["\'](.*?)["\']', form_html, re.IGNORECASE)
        method = method_match.group(1).upper() if method_match else 'GET'
        # Get inputs
        inputs = []
        input_pattern = re.compile(r'<input[^>]*name=["\'](.*?)["\'][^>]*>', re.IGNORECASE)
        for inp_match in input_pattern.finditer(form_html):
            name = inp_match.group(1)
            if name:
                inputs.append({'name': name, 'type': 'text'})
        forms.append({
            'action': urljoin(base_url, action),
            'method': method,
            'inputs': inputs
        })
    return forms

def extract_params(url: str) -> Dict[str, List[str]]:
    return parse_qs(urlparse(url).query)

def add_param_to_url(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = [value]
    new_qs = urlencode(qs, doseq=True)
    return parsed._replace(query=new_qs).geturl()

# --------------------------- Vulnerability Class -------------------------
class Vulnerability:
    def __init__(self, name: str, url: str, severity: str, description: str,
                 parameter: str = "", payload: str = "", evidence: str = ""):
        self.name = name
        self.url = url
        self.severity = severity
        self.description = description
        self.parameter = parameter
        self.payload = payload
        self.evidence = evidence
        self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'url': self.url,
            'severity': self.severity,
            'description': self.description,
            'parameter': self.parameter,
            'payload': self.payload,
            'evidence': self.evidence,
            'timestamp': self.timestamp
        }

# --------------------------- HTTP Client (Synchronous Fallback) ---------
class SimpleHTTPClient:
    """Simple HTTP client using urllib (always works)"""
    
    @staticmethod
    def get(url: str, timeout: int = TIMEOUT) -> Tuple[Optional[str], Optional[Dict], Optional[int]]:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': DEFAULT_USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout, context=ssl._create_unverified_context()) as resp:
                content = resp.read().decode('utf-8', errors='ignore')
                headers = dict(resp.getheaders())
                return content, headers, resp.status
        except Exception as e:
            return None, None, None
    
    @staticmethod
    def post(url: str, data: Dict, timeout: int = TIMEOUT) -> Tuple[Optional[str], Optional[Dict], Optional[int]]:
        try:
            encoded_data = urllib.parse.urlencode(data).encode('utf-8')
            req = urllib.request.Request(url, data=encoded_data, headers={'User-Agent': DEFAULT_USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout, context=ssl._create_unverified_context()) as resp:
                content = resp.read().decode('utf-8', errors='ignore')
                headers = dict(resp.getheaders())
                return content, headers, resp.status
        except Exception:
            return None, None, None

# --------------------------- Scanner Core (Synchronous) ----------------
class WebScanner:
    def __init__(self, target_url: str, max_depth: int = MAX_DEPTH):
        self.target_url = normalize_url(target_url)
        self.domain = get_domain(self.target_url)
        self.max_depth = max_depth
        self.visited_urls = set()
        self.crawled_pages = []  # (url, depth, html)
        self.vulnerabilities = []
        self.http = SimpleHTTPClient()
    
    def crawl(self, start_url: str, depth: int = 0):
        """Crawl the website synchronously"""
        if depth > self.max_depth or start_url in self.visited_urls:
            return
        self.visited_urls.add(start_url)
        print(f"{SafeColors.CYAN}[*] Crawling: {start_url} (depth {depth}){SafeColors.RESET}")
        
        html, headers, status = self.http.get(start_url)
        if not html or status >= 400:
            return
        
        self.crawled_pages.append((start_url, depth, html))
        
        # Extract links
        links = extract_links_simple(html, start_url)
        
        for link in links:
            if is_same_domain(self.target_url, link) and link not in self.visited_urls:
                self.crawl(link, depth + 1)
                time.sleep(RATE_LIMIT)
    
    # -------------------- Vulnerability Tests --------------------
    def test_sql_injection(self, url: str, param: str, method: str = 'GET', post_data: Dict = None) -> List[Vulnerability]:
        findings = []
        original_content = None
        
        # Get baseline
        if method == 'GET':
            orig_html, _, _ = self.http.get(url)
        else:
            orig_html, _, _ = self.http.post(url, post_data or {})
        if orig_html:
            original_content = orig_html
        
        for payload, payload_type in SQL_PAYLOADS:
            test_url = url
            test_data = None
            if method == 'GET':
                test_url = add_param_to_url(url, param, payload)
            else:
                test_data = (post_data or {}).copy()
                test_data[param] = payload
            
            if method == 'GET':
                html, _, _ = self.http.get(test_url)
            else:
                html, _, _ = self.http.post(url, test_data)
            
            if not html:
                continue
            
            if payload_type == 'error':
                for pattern in SQL_ERROR_PATTERNS:
                    if re.search(pattern, html, re.IGNORECASE):
                        findings.append(Vulnerability(
                            name="SQL Injection (Error Based)",
                            url=url,
                            severity="High",
                            description=f"Database error for parameter '{param}'",
                            parameter=param,
                            payload=payload,
                            evidence=re.search(pattern, html, re.IGNORECASE).group(0)
                        ))
                        break
            elif payload_type == 'boolean' and original_content:
                if '1=1' in payload and len(html) != len(original_content):
                    findings.append(Vulnerability(
                        name="SQL Injection (Boolean Based)",
                        url=url,
                        severity="High",
                        description=f"Boolean-based injection possible for '{param}'",
                        parameter=param,
                        payload=payload,
                        evidence="Content length differs"
                    ))
        return findings
    
    def test_xss(self, url: str, param: str, method: str = 'GET', post_data: Dict = None) -> List[Vulnerability]:
        findings = []
        for payload in XSS_PAYLOADS:
            test_url = url
            test_data = None
            if method == 'GET':
                test_url = add_param_to_url(url, param, payload)
            else:
                test_data = (post_data or {}).copy()
                test_data[param] = payload
            
            if method == 'GET':
                html, _, _ = self.http.get(test_url)
            else:
                html, _, _ = self.http.post(url, test_data)
            
            if html and payload in html:
                findings.append(Vulnerability(
                    name="Cross-Site Scripting (Reflected)",
                    url=url,
                    severity="High",
                    description=f"XSS payload reflected for parameter '{param}'",
                    parameter=param,
                    payload=payload,
                    evidence=f"Payload found: {payload[:50]}"
                ))
                break
        return findings
    
    def test_open_redirect(self, url: str, param: str) -> List[Vulnerability]:
        findings = []
        for payload in OPEN_REDIRECT_PAYLOADS:
            test_url = add_param_to_url(url, param, payload)
            try:
                req = urllib.request.Request(test_url, headers={'User-Agent': DEFAULT_USER_AGENT})
                req.get_method = lambda: 'GET'
                with urllib.request.urlopen(req, timeout=TIMEOUT, context=ssl._create_unverified_context()) as resp:
                    final_url = resp.geturl()
                    if 'evil.com' in final_url or 'google.com' in final_url:
                        findings.append(Vulnerability(
                            name="Open Redirect",
                            url=url,
                            severity="Medium",
                            description=f"Parameter '{param}' redirects to external",
                            parameter=param,
                            payload=payload,
                            evidence=f"Redirected to {final_url}"
                        ))
                        break
            except:
                pass
        return findings
    
    def test_directory_discovery(self) -> List[Vulnerability]:
        findings = []
        for directory in COMMON_DIRS:
            test_url = urljoin(self.target_url, directory + '/')
            _, _, status = self.http.get(test_url)
            if status in [200, 403, 401]:
                findings.append(Vulnerability(
                    name="Directory Discovery",
                    url=test_url,
                    severity="Low" if status == 200 else "Medium",
                    description=f"Accessible directory: {directory}",
                    evidence=f"HTTP {status}"
                ))
        return findings
    
    def test_sensitive_files(self) -> List[Vulnerability]:
        findings = []
        for file in SENSITIVE_FILES:
            test_url = urljoin(self.target_url, file)
            _, _, status = self.http.get(test_url)
            if status == 200:
                findings.append(Vulnerability(
                    name="Sensitive File Exposure",
                    url=test_url,
                    severity="High",
                    description=f"Sensitive file exposed: {file}",
                    evidence="HTTP 200 OK"
                ))
        return findings
    
    def analyze_security_headers(self, url: str) -> List[Vulnerability]:
        findings = []
        _, headers, _ = self.http.get(url)
        if headers:
            required = {
                'X-Frame-Options': 'Clickjacking protection missing',
                'X-Content-Type-Options': 'MIME sniffing protection missing',
                'Strict-Transport-Security': 'HSTS not enforced'
            }
            for header, desc in required.items():
                if header not in headers:
                    findings.append(Vulnerability(
                        name="Missing Security Header",
                        url=url,
                        severity="Low",
                        description=f"{header} missing. {desc}"
                    ))
        return findings
    
    def analyze_cookies(self, url: str) -> List[Vulnerability]:
        findings = []
        _, headers, _ = self.http.get(url)
        if headers:
            set_cookie = headers.get('Set-Cookie', '')
            if set_cookie:
                if 'HttpOnly' not in set_cookie:
                    findings.append(Vulnerability(
                        name="Cookie Missing HttpOnly",
                        url=url,
                        severity="Medium",
                        description="Cookie accessible via JavaScript"
                    ))
                if 'Secure' not in set_cookie:
                    findings.append(Vulnerability(
                        name="Cookie Missing Secure Flag",
                        url=url,
                        severity="Medium",
                        description="Cookie sent over HTTP"
                    ))
        return findings
    
    def test_ssrf(self, url: str, param: str) -> List[Vulnerability]:
        findings = []
        for payload in SSRF_PAYLOADS:
            test_url = add_param_to_url(url, param, payload)
            html, _, _ = self.http.get(test_url)
            if html:
                indicators = ['127.0.0.1', 'localhost', 'connection refused', 'internal server']
                if any(ind in html.lower() for ind in indicators):
                    findings.append(Vulnerability(
                        name="Potential SSRF",
                        url=url,
                        severity="High",
                        description=f"Parameter '{param}' may allow SSRF",
                        parameter=param,
                        payload=payload,
                        evidence="Internal address reference in response"
                    ))
                    break
        return findings
    
    def scan_page(self, url: str, depth: int, html: str):
        print(f"{SafeColors.GREEN}[+] Scanning: {url}{SafeColors.RESET}")
        
        # Headers & cookies
        self.vulnerabilities.extend(self.analyze_security_headers(url))
        self.vulnerabilities.extend(self.analyze_cookies(url))
        
        # URL parameters
        params = extract_params(url)
        for param in params:
            self.vulnerabilities.extend(self.test_sql_injection(url, param))
            self.vulnerabilities.extend(self.test_xss(url, param))
            self.vulnerabilities.extend(self.test_open_redirect(url, param))
            self.vulnerabilities.extend(self.test_ssrf(url, param))
        
        # Forms
        forms = extract_forms_simple(html, url)
        
        for form in forms:
            action = form['action']
            method = form['method']
            for inp in form['inputs']:
                pname = inp['name']
                if method == 'GET':
                    self.vulnerabilities.extend(self.test_sql_injection(action, pname))
                    self.vulnerabilities.extend(self.test_xss(action, pname))
                else:
                    self.vulnerabilities.extend(self.test_sql_injection(action, pname, method='POST', post_data={pname: 'test'}))
                    self.vulnerabilities.extend(self.test_xss(action, pname, method='POST', post_data={pname: 'test'}))
    
    def run_full_scan(self):
        print(f"{SafeColors.MAGENTA}\n[+] Starting scan on {self.target_url}{SafeColors.RESET}")
        start_time = time.time()
        
        # Crawl
        print(f"{SafeColors.CYAN}[*] Crawling...{SafeColors.RESET}")
        self.crawl(self.target_url, 0)
        print(f"{SafeColors.GREEN}[+] Crawled {len(self.crawled_pages)} pages.{SafeColors.RESET}")
        
        # Scan each page
        for url, depth, html in self.crawled_pages:
            self.scan_page(url, depth, html)
        
        # Additional tests
        print(f"{SafeColors.YELLOW}[*] Directory & file discovery...{SafeColors.RESET}")
        self.vulnerabilities.extend(self.test_directory_discovery())
        self.vulnerabilities.extend(self.test_sensitive_files())
        
        elapsed = time.time() - start_time
        print(f"{SafeColors.GREEN}\n[+] Scan completed in {elapsed:.2f}s. Found {len(self.vulnerabilities)} issues.{SafeColors.RESET}")
        return self.vulnerabilities

# --------------------------- Report Generator ---------------------------
class ReportGenerator:
    def __init__(self, target_url: str, vulnerabilities: List[Vulnerability]):
        self.target_url = target_url
        self.vulnerabilities = vulnerabilities
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs("scan_reports", exist_ok=True)
    
    def save_json(self) -> str:
        fname = f"scan_reports/scan_{self.timestamp}.json"
        data = {
            "target": self.target_url,
            "date": self.timestamp,
            "total": len(self.vulnerabilities),
            "findings": [v.to_dict() for v in self.vulnerabilities]
        }
        with open(fname, 'w') as f:
            json.dump(data, f, indent=2)
        return fname
    
    def save_csv(self) -> str:
        fname = f"scan_reports/scan_{self.timestamp}.csv"
        with open(fname, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Name", "URL", "Severity", "Parameter", "Payload", "Description", "Evidence"])
            for v in self.vulnerabilities:
                writer.writerow([v.name, v.url, v.severity, v.parameter, v.payload, v.description, v.evidence])
        return fname
    
    def save_html(self) -> str:
        fname = f"scan_reports/scan_{self.timestamp}.html"
        html = f"""<!DOCTYPE html>
<html>
<head><title>Scan Report - {self.target_url}</title>
<style>
body{{font-family:Arial;margin:20px}}
.high{{color:red;font-weight:bold}}
.medium{{color:orange}}
.low{{color:blue}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ddd;padding:8px;text-align:left}}
th{{background:#f2f2f2}}
</style>
</head>
<body>
<h1>Web Vulnerability Scan Report</h1>
<p><strong>Target:</strong> {self.target_url}</p>
<p><strong>Date:</strong> {self.timestamp}</p>
<p><strong>Total Issues:</strong> {len(self.vulnerabilities)}</p>
<table>
<tr><th>Severity</th><th>Name</th><th>URL</th><th>Parameter</th><th>Description</th></tr>
"""
        for v in self.vulnerabilities:
            html += f"""
<tr>
<td class="{v.severity.lower()}">{v.severity}</td>
<td>{v.name}</td>
<td>{v.url}</td>
<td>{v.parameter}</td>
<td>{v.description}</td>
</tr>
"""
        html += "</table></body></html>"
        with open(fname, 'w', encoding='utf-8') as f:
            f.write(html)
        return fname
    
    def generate_all(self):
        j = self.save_json()
        c = self.save_csv()
        h = self.save_html()
        print(f"{SafeColors.GREEN}[+] Reports saved:\n  JSON: {j}\n  CSV: {c}\n  HTML: {h}{SafeColors.RESET}")

# --------------------------- Session Management ---------------------------
class SessionManager:
    def __init__(self, file="session.json"):
        self.file = file
    
    def save(self, scanner: WebScanner, vulns: List[Vulnerability]):
        data = {
            "target": scanner.target_url,
            "max_depth": scanner.max_depth,
            "visited": list(scanner.visited_urls),
            "crawled": [(url, depth) for url, depth, _ in scanner.crawled_pages],
            "vulnerabilities": [v.to_dict() for v in vulns],
            "timestamp": datetime.now().isoformat()
        }
        with open(self.file, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"{SafeColors.GREEN}[+] Session saved to {self.file}{SafeColors.RESET}")
    
    def load(self) -> Optional[Dict]:
        if not os.path.exists(self.file):
            return None
        with open(self.file, 'r') as f:
            return json.load(f)

# --------------------------- WAF Detection ---------------------------
def detect_waf(url: str) -> bool:
    test_url = add_param_to_url(url, "id", "'")
    try:
        req = urllib.request.Request(test_url, headers={'User-Agent': DEFAULT_USER_AGENT})
        with urllib.request.urlopen(req, timeout=5, context=ssl._create_unverified_context()) as resp:
            headers = dict(resp.getheaders())
            for w in WAF_HEADERS:
                if w in headers:
                    return True
            return resp.status in [403, 406]
    except:
        return False

# --------------------------- Interactive Menu ---------------------------
def print_banner():
    print(f"""{SafeColors.CYAN}
╔══════════════════════════════════════════════════════════════╗
║      Advanced Web Vulnerability Scanner - Ethical Edition    ║
║                    Authorized Use Only                        ║
╚══════════════════════════════════════════════════════════════╝
{SafeColors.RESET}""")

def main():
    print_banner()
    while True:
        print("\n1. Start New Scan")
        print("2. Load Previous Session")
        print("3. View Last Report")
        print("4. Exit")
        choice = input("[?] Select option: ").strip()
        
        if choice == '1':
            target = input("[?] Target URL: ").strip()
            if not is_valid_url(target):
                print(f"{SafeColors.RED}[!] Invalid URL{SafeColors.RESET}")
                continue
            
            depth_input = input(f"[?] Max depth (default {MAX_DEPTH}): ").strip()
            depth = int(depth_input) if depth_input.isdigit() else MAX_DEPTH
            
            print(f"{SafeColors.CYAN}[*] Checking WAF...{SafeColors.RESET}")
            if detect_waf(target):
                print(f"{SafeColors.YELLOW}[!] WAF detected. Some tests may be blocked.{SafeColors.RESET}")
            else:
                print(f"{SafeColors.GREEN}[+] No obvious WAF.{SafeColors.RESET}")
            
            scanner = WebScanner(target, max_depth=depth)
            vulns = scanner.run_full_scan()
            
            rep = ReportGenerator(target, vulns)
            rep.generate_all()
            
            sess = SessionManager()
            sess.save(scanner, vulns)
            
        elif choice == '2':
            sess = SessionManager()
            data = sess.load()
            if not data:
                print(f"{SafeColors.RED}[!] No session found.{SafeColors.RESET}")
                continue
            print(f"{SafeColors.GREEN}[+] Loaded session for {data['target']} with {len(data['vulnerabilities'])} findings.{SafeColors.RESET}")
            # Recreate vulnerabilities
            vulns = []
            for vd in data['vulnerabilities']:
                v = Vulnerability(vd['name'], vd['url'], vd['severity'], vd['description'],
                                  vd.get('parameter',''), vd.get('payload',''), vd.get('evidence',''))
                vulns.append(v)
            rep = ReportGenerator(data['target'], vulns)
            rep.generate_all()
            
        elif choice == '3':
            import glob
            reports = glob.glob("scan_reports/*.html") + glob.glob("scan_reports/*.json")
            if not reports:
                print(f"{SafeColors.RED}[!] No reports found.{SafeColors.RESET}")
                continue
            latest = max(reports, key=os.path.getctime)
            print(f"{SafeColors.GREEN}[+] Latest report: {latest}{SafeColors.RESET}")
            if latest.endswith('.html'):
                try:
                    import webbrowser
                    webbrowser.open(latest)
                except:
                    print("[!] Could not open browser.")
            else:
                with open(latest, 'r') as f:
                    print(f.read())
                    
        elif choice == '4':
            print(f"{SafeColors.MAGENTA}[+] Exiting. Stay ethical!{SafeColors.RESET}")
            break
        else:
            print(f"{SafeColors.RED}[!] Invalid choice.{SafeColors.RESET}")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()