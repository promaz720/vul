"""Lightweight vulnerability checks for demonstration purposes."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import warnings

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

# Suppress SSL warnings for self-signed certificates
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
urllib3_logger = __import__('logging').getLogger('urllib3')
urllib3_logger.setLevel(__import__('logging').CRITICAL)

# User agents to bypass basic bot detection
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
]

HEADERS = {
    "User-Agent": USER_AGENTS[0],
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1"
}

REQUEST_TIMEOUT = 5  # Reduced from 8
MAX_CRAWL_PAGES = 5  # Reduced from 10 for faster crawling
MAX_URL_SCAN = 5  # Reduced from 10
MAX_FORMS_SCAN = 3  # Reduced from 5
MAX_FORM_PARAMS = 2  # Reduced from 3
MAX_THREADS = 4  # Parallel processing


@dataclass
class Finding:
    title: str
    severity: str
    description: str
    recommendation: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    path: Optional[str] = None
    poc: Optional[str] = None


@dataclass
class ScanResult:
    target: str
    findings: List[Finding]
    metadata: Dict[str, Any] = field(default_factory=dict)


def run_scans(target_url: str) -> ScanResult:
    normalized_url = normalize_url(target_url)
    findings: List[Finding] = []
    metadata = {}

    try:
        response = requests.get(
            normalized_url, 
            timeout=REQUEST_TIMEOUT, 
            allow_redirects=True,
            headers=HEADERS,
            verify=False
        )
        response.raise_for_status()
    except requests.exceptions.Timeout:
        findings.append(
            Finding(
                title="Request Timeout",
                severity="Medium",
                description=f"The request to {normalized_url} timed out after {REQUEST_TIMEOUT} seconds.",
                recommendation="The target may be slow or unresponsive. Try again later or increase timeout.",
            )
        )
        return ScanResult(target=normalized_url, findings=findings, metadata=metadata)
    except requests.exceptions.ConnectionError as e:
        findings.append(
            Finding(
                title="Connection Error",
                severity="High",
                description=f"Could not connect to {normalized_url}. Error: {str(e)[:100]}",
                recommendation="Verify the URL is correct and the host is online.",
            )
        )
        return ScanResult(target=normalized_url, findings=findings, metadata=metadata)
    except requests.exceptions.HTTPError as e:
        findings.append(
            Finding(
                title=f"HTTP Error {e.response.status_code}",
                severity="High" if e.response.status_code >= 500 else "Medium",
                description=f"Server returned {e.response.status_code}: {e.response.reason}",
                recommendation="Check if the URL is correct or if the server is properly configured.",
            )
        )
        return ScanResult(target=normalized_url, findings=findings, metadata=metadata)
    except Exception as exc:  # Broad catch to include connection issues.
        findings.append(
            Finding(
                title="Target Unreachable",
                severity="High",
                description=f"Could not reach {normalized_url}. {str(exc)[:100]}",
                recommendation="Verify that the host is online and reachable from the scanner.",
            )
        )
        return ScanResult(target=normalized_url, findings=findings, metadata=metadata)

    # Crawl the site
    crawl_result = crawl_site(normalized_url, max_pages=MAX_CRAWL_PAGES)
    all_urls = crawl_result['urls'] + [normalized_url]
    all_forms = crawl_result['forms']

    # Remove duplicates
    all_urls = list(set(all_urls))

    # Check surface-level issues
    findings.extend(check_security_headers(response))
    findings.extend(check_https_usage(normalized_url))
    findings.extend(check_robots_disclosure(normalized_url))
    findings.extend(check_csrf(all_forms))

    # Deep scan: test URLs and forms with parallel processing
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = []
        
        # Scan URLs in parallel
        for url in all_urls[:MAX_URL_SCAN]:
            parsed = urlparse(url)
            if parsed.query:
                existing_params = list(parse_qs(parsed.query).keys())
                param_names = existing_params + ['test']
            else:
                param_names = ['q', 'search', 'query', 'id', 'user'][:2]  # Limit params
            
            for param in param_names:
                futures.append(executor.submit(check_sql_injection, url, param))
                futures.append(executor.submit(check_reflected_xss, url, param))
                futures.append(executor.submit(check_command_injection, url, param))
                futures.append(executor.submit(check_path_traversal, url, param))
        
        # Scan forms in parallel
        for form in all_forms[:MAX_FORMS_SCAN]:
            for param in form['inputs'][:MAX_FORM_PARAMS]:
                if form['method'] == 'GET':
                    futures.append(executor.submit(check_sql_injection, form['url'], param))
                    futures.append(executor.submit(check_reflected_xss, form['url'], param))
                    futures.append(executor.submit(check_command_injection, form['url'], param))
                    futures.append(executor.submit(check_path_traversal, form['url'], param))
        
        # Collect results
        for future in as_completed(futures):
            try:
                results = future.result()
                findings.extend(results)
            except Exception:
                pass

    # Deduplicate findings based on title and param to avoid repetition
    unique_findings = {}
    for f in findings:
        key = (f.title, f.evidence.get('param', ''))
        if key not in unique_findings:
            unique_findings[key] = f
    findings = list(unique_findings.values())

    metadata = {
        "status_code": response.status_code,
        "final_url": response.url,
        "headers": dict(response.headers),
        "crawled_urls": len(all_urls),
        "crawled_forms": len(all_forms),
    }

    return ScanResult(target=normalized_url, findings=findings, metadata=metadata)


def normalize_url(url: str) -> str:
    if url.startswith("http://") or url.startswith("https://"):
        return url
    return f"https://{url}"


def check_security_headers(response: requests.Response) -> List[Finding]:
    required_headers = {
        "Content-Security-Policy": "CSP helps mitigate XSS and data injection attacks.",
        "Strict-Transport-Security": "HSTS enforces HTTPS, preventing protocol downgrade attacks.",
        "X-Content-Type-Options": "Stops MIME type sniffing for some attacks.",
        "X-Frame-Options": "Protects against clickjacking.",
        "Permissions-Policy": "Restricts powerful browser features to mitigate abuse.",
    }

    findings: List[Finding] = []
    for header_name, rationale in required_headers.items():
        if header_name not in response.headers:
            findings.append(
                Finding(
                    title=f"Missing Security Header: {header_name}",
                    severity="Medium",
                    description=f"The response is missing {header_name}. {rationale}",
                    recommendation=f"Add {header_name} to improve protection.",
                )
            )
    return findings


def check_https_usage(url: str) -> List[Finding]:
    if url.startswith("https://"):
        return []
    return [
        Finding(
            title="Insecure Protocol",
            severity="High",
            description=f"The site is accessed using HTTP: {url}",
            recommendation="Force HTTPS by setting up TLS and redirecting HTTP to HTTPS.",
        )
    ]


def check_robots_disclosure(url: str) -> List[Finding]:
    robots_url = urljoin(url if url.endswith("/") else url + "/", "robots.txt")
    try:
        response = requests.get(robots_url, timeout=REQUEST_TIMEOUT, headers=HEADERS, verify=False)
    except Exception:
        return []

    findings: List[Finding] = []
    if response.status_code == 200 and "Disallow" in response.text:
        findings.append(
            Finding(
                title="Sensitive Paths Possibly Exposed",
                severity="Low",
                description="robots.txt discloses directories that might contain sensitive content.",
                recommendation="Review directives in robots.txt and do not rely on robots to hide sensitive paths.",
                evidence={"robots.txt": response.text[:2000]},
            )
        )
    return findings


SQL_PAYLOADS = ["' OR 1=1--", "' UNION SELECT NULL--", "'; DROP TABLE test--", "'; EXEC xp_cmdshell('net user')--", "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --"]
XSS_PAYLOADS = ["<script>alert('xss')</script>", "<img src=x onerror=alert('xss')>", "'><script>alert('xss')</script>", "<iframe src='javascript:alert(`xss`)'>", "<svg onload=alert('xss')>"]
COMMAND_INJ_PAYLOADS = ["; ls -la", "| whoami", "`whoami`", "$(whoami)", "; cat /etc/passwd", "| ping localhost", "`uname -a`"]
PATH_TRAVERSAL_PAYLOADS = ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "../../../../boot.ini", "../../../web.config"]


def crawl_site(base_url: str, max_pages: int = 10) -> Dict[str, Any]:
    """Crawl the site to collect URLs and forms."""
    visited = set()
    to_visit = [base_url]
    found_urls = []
    found_forms = []

    while to_visit and len(found_urls) < max_pages:
        url = to_visit.pop(0)
        if url in visited or not url.startswith(base_url):
            continue
        visited.add(url)
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=HEADERS, verify=False)
            if response.status_code != 200:
                continue
            soup = BeautifulSoup(response.content, 'html.parser')  # Faster than lxml
            # Find links (limit to 15 per page for speed)
            for link in soup.find_all('a', href=True)[:15]:
                href = urljoin(url, link['href'])
                if href not in visited and href.startswith(base_url):
                    to_visit.append(href)
                    found_urls.append(href)
            # Find forms (limit to 5 per page)
            for form in soup.find_all('form')[:5]:
                action = urljoin(url, form.get('action', '')) or url
                method = form.get('method', 'GET').upper()
                inputs = []
                for inp in form.find_all(['input', 'textarea', 'select'])[:5]:
                    name = inp.get('name')
                    if name:
                        inputs.append(name)
                if inputs:
                    found_forms.append({'url': action, 'method': method, 'inputs': inputs})
        except:
            continue
    return {'urls': found_urls, 'forms': found_forms}


def check_sql_injection(url: str, param_name: str = "q") -> List[Finding]:
    findings: List[Finding] = []
    for payload in SQL_PAYLOADS:
        params = {param_name: payload}
        try:
            response = requests.get(url, params=params, timeout=REQUEST_TIMEOUT, headers=HEADERS, verify=False)
        except Exception:
            continue
        if any(keyword in response.text.lower() for keyword in ("sql syntax", "sql error", "database error")):
            findings.append(
                Finding(
                    title="Potential SQL Injection",
                    severity="High",
                    description="Error strings detected when sending SQL injection payloads in query parameters.",
                    recommendation="Sanitize database inputs and use parameterized queries.",
                    evidence={"payload": payload, "param": param_name, "url": response.url},
                    path=response.url,
                    poc=f"Use a proxy like Burp to send GET {response.url.replace('&', '&')} navigating to this URL in a browser to observe the error.",
                )
            )
            break
    return findings


def check_reflected_xss(url: str, param_name: str = "xss") -> List[Finding]:
    findings: List[Finding] = []
    for payload in XSS_PAYLOADS:
        try:
            response = requests.get(url, params={param_name: payload}, timeout=REQUEST_TIMEOUT, headers=HEADERS, verify=False)
        except Exception:
            continue

        if payload in response.text:
            findings.append(
                Finding(
                    title="Reflected XSS",
                    severity="High",
                    description="XSS payload was reflected in the response without sanitization.",
                    recommendation="Encode untrusted input before rendering and implement a CSP.",
                    evidence={"payload": payload, "param": param_name, "url": response.url},
                    path=response.url,
                    poc=f"Navigate to {response.url} in a browser to see the popup.",
                )
            )
            break
    return findings


def check_command_injection(url: str, param_name: str = "cmd") -> List[Finding]:
    findings: List[Finding] = []
    for payload in COMMAND_INJ_PAYLOADS:
        params = {param_name: payload}
        try:
            response = requests.get(url, params=params, timeout=REQUEST_TIMEOUT, headers=HEADERS, verify=False)
        except Exception:
            continue
        if ("root:" in response.text or "/bin/bash" in response.text or "command not found" not in response.text and len(response.text.split('\n')) > 1):
            findings.append(
                Finding(
                    title="Potential Command Injection",
                    severity="High",
                    description="Command injection payload appears to have executed.",
                    recommendation="Use safe functions for system calls and validate input.",
                    evidence={"payload": payload, "param": param_name, "url": response.url, "response_snippet": response.text[:500]},
                    path=response.url,
                    poc=f"Send GET request to {response.url} to execute commands.",
                )
            )
            break
    return findings


def check_path_traversal(url: str, param_name: str = "file") -> List[Finding]:
    findings: List[Finding] = []
    for payload in PATH_TRAVERSAL_PAYLOADS:
        params = {param_name: payload}
        try:
            response = requests.get(url, params=params, timeout=REQUEST_TIMEOUT, headers=HEADERS, verify=False)
        except Exception:
            continue
        if "root:" in response.text or "[boot loader]" in response.text or any(keyword in response.text for keyword in ["passwd", "etc"]):
            findings.append(
                Finding(
                    title="Potential Path Traversal",
                    severity="High",
                    description="Path traversal payload seems to have accessed sensitive files.",
                    recommendation="Restrict file access to a whitelist and resolve paths.",
                    evidence={"payload": payload, "param": param_name, "url": response.url, "response_snippet": response.text[:500]},
                    path=response.url,
                    poc=f"Use GET {response.url} to view system files.",
                )
            )
            break
    return findings


def check_csrf(forms: List[Dict[str, Any]]) -> List[Finding]:
    findings: List[Finding] = []
    for form in forms:
        url = form['url']
        method = form['method']
        inputs = form['inputs']
        if method == 'POST' and 'csrf' not in ' '.join(inputs).lower() and 'token' not in ' '.join(inputs).lower():
            findings.append(
                Finding(
                    title="Potential Missing CSRF Protection",
                    severity="Medium",
                    description=f"Form at {url} does not appear to have CSRF token.",
                    recommendation="Implement CSRF tokens to prevent state-changing actions.",
                    evidence={"form_url": url, "method": method, "inputs": inputs},
                    path=url,
                    poc="Forge a POST request without valid authentication.",
                )
            )
    return findings
