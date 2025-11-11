import os
import subprocess
import shutil
import re
import time
import hashlib
import json
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs
import requests
from bs4 import BeautifulSoup
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from concurrent.futures import ThreadPoolExecutor, as_completed

# VirusTotal API Key
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')

# ==============================
# OWASP TOP 10 SCANNER (Enhanced)
# ==============================
class OWASPScanner:
    """
    Enhanced scanner focusing on OWASP Top 10 vulnerabilities
    Only reports genuine, exploitable vulnerabilities
    """
    
    def __init__(self, base_url, timeout=10):
        self.base_url = self._normalize_url(base_url)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerabilities = []
        self.crawled_urls = set()
        self.max_crawl = 30
        self.forms_tested = set()

    def _normalize_url(self, url):
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")

    def _safe_get(self, url, **kwargs):
        try:
            return self.session.get(url, timeout=self.timeout, verify=True, **kwargs)
        except requests.exceptions.SSLError:
            # Retry without verification if SSL fails
            try:
                return self.session.get(url, timeout=self.timeout, verify=False, **kwargs)
            except:
                return None
        except:
            return None

    def _safe_post(self, url, **kwargs):
        try:
            return self.session.post(url, timeout=self.timeout, verify=True, **kwargs)
        except:
            return None

    def comprehensive_scan(self):
        """Run all OWASP Top 10 checks"""
        self.vulnerabilities = []
        
        print("[*] Starting OWASP Top 10 Security Scan...")
        
        # A01:2021 – Broken Access Control
        self._test_broken_access_control()
        
        # A02:2021 – Cryptographic Failures
        self._test_cryptographic_failures()
        
        # A03:2021 – Injection
        self._test_injection_vulnerabilities()
        
        # A04:2021 – Insecure Design
        self._test_insecure_design()
        
        # A05:2021 – Security Misconfiguration
        self._test_security_misconfiguration()
        
        # A06:2021 – Vulnerable and Outdated Components
        self._test_outdated_components()
        
        # A07:2021 – Identification and Authentication Failures
        self._test_authentication_failures()
        
        # A08:2021 – Software and Data Integrity Failures
        self._test_integrity_failures()
        
        # A09:2021 – Security Logging and Monitoring Failures
        self._test_logging_monitoring()
        
        # A10:2021 – Server-Side Request Forgery (SSRF)
        self._test_ssrf()
        
        return {
            'vulnerabilities': self.vulnerabilities,
            'total_critical': sum(1 for v in self.vulnerabilities if v['severity'] == 'Critical'),
            'total_high': sum(1 for v in self.vulnerabilities if v['severity'] == 'High'),
            'total_medium': sum(1 for v in self.vulnerabilities if v['severity'] == 'Medium'),
            'total_low': sum(1 for v in self.vulnerabilities if v['severity'] == 'Low')
        }

    # ==============================
    # A01:2021 – Broken Access Control
    # ==============================
    def _test_broken_access_control(self):
        """Test for broken access control vulnerabilities"""
        print("[*] Testing A01: Broken Access Control...")
        
        # Test for exposed admin panels
        admin_paths = [
            'admin', 'administrator', 'admin.php', 'admin/', 
            'wp-admin', 'wp-login.php', 'administrator/',
            'phpmyadmin', 'pma', 'mysql', 'db',
            'cpanel', 'webmail', 'controlpanel',
            'dashboard', 'manager', 'management'
        ]
        
        exposed_admin = []
        for path in admin_paths:
            url = urljoin(self.base_url + '/', path)
            resp = self._safe_get(url, allow_redirects=True)
            if resp and resp.status_code == 200:
                # Check if it's actually an admin panel
                content_lower = resp.text.lower()
                if any(keyword in content_lower for keyword in ['login', 'username', 'password', 'admin']):
                    exposed_admin.append(path)
        
        if exposed_admin:
            self.vulnerabilities.append({
                'owasp_id': 'A01:2021',
                'type': 'Exposed Administrative Interface',
                'severity': 'High',
                'description': f'Admin panels accessible without authentication: {", ".join(exposed_admin[:5])}',
                'evidence': f'URLs: {", ".join([urljoin(self.base_url, p) for p in exposed_admin[:3]])}',
                'recommendation': 'Implement IP whitelisting, strong authentication, and hide admin paths. Use /admin-[random-string] or implement VPN access.',
                'cwe': 'CWE-284',
                'references': 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
            })
        
        # Test for directory traversal
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd'
        ]
        
        resp = self._safe_get(self.base_url)
        if resp:
            soup = BeautifulSoup(resp.text, 'html.parser')
            links = soup.find_all('a', href=True)
            
            for link in links[:10]:  # Test first 10 links
                href = link['href']
                if '?' in href and '=' in href:
                    for payload in traversal_payloads:
                        test_url = href.split('=')[0] + '=' + payload
                        full_url = urljoin(self.base_url, test_url)
                        test_resp = self._safe_get(full_url)
                        
                        if test_resp and test_resp.status_code == 200:
                            if 'root:' in test_resp.text or '[extensions]' in test_resp.text:
                                self.vulnerabilities.append({
                                    'owasp_id': 'A01:2021',
                                    'type': 'Directory Traversal',
                                    'severity': 'Critical',
                                    'description': 'Path traversal vulnerability allows reading arbitrary files',
                                    'evidence': f'Payload: {payload} | URL: {full_url}',
                                    'recommendation': 'Implement strict input validation, use whitelisting for file access, and avoid direct file path concatenation.',
                                    'cwe': 'CWE-22',
                                    'references': 'https://owasp.org/www-community/attacks/Path_Traversal'
                                })
                                break

    # ==============================
    # A02:2021 – Cryptographic Failures
    # ==============================
    def _test_cryptographic_failures(self):
        """Test for cryptographic failures"""
        print("[*] Testing A02: Cryptographic Failures...")
        
        # Check if site uses HTTPS
        if not self.base_url.startswith('https://'):
            self.vulnerabilities.append({
                'owasp_id': 'A02:2021',
                'type': 'Missing HTTPS Encryption',
                'severity': 'Critical',
                'description': 'Website does not use HTTPS encryption',
                'evidence': f'URL: {self.base_url}',
                'recommendation': 'Implement SSL/TLS certificate and force all HTTP traffic to redirect to HTTPS.',
                'cwe': 'CWE-319',
                'references': 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'
            })
            return
        
        # Check SSL/TLS configuration
        resp = self._safe_get(self.base_url)
        if resp:
            # Check for HSTS
            if 'strict-transport-security' not in [h.lower() for h in resp.headers.keys()]:
                self.vulnerabilities.append({
                    'owasp_id': 'A02:2021',
                    'type': 'Missing HSTS Header',
                    'severity': 'High',
                    'description': 'HTTP Strict Transport Security (HSTS) not implemented',
                    'evidence': 'No Strict-Transport-Security header found',
                    'recommendation': 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
                    'cwe': 'CWE-523',
                    'references': 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html'
                })
            
            # Check for mixed content
            if resp.text:
                http_resources = re.findall(r'http://[^\s<>"\']+', resp.text)
                if http_resources:
                    self.vulnerabilities.append({
                        'owasp_id': 'A02:2021',
                        'type': 'Mixed Content (HTTP in HTTPS)',
                        'severity': 'Medium',
                        'description': f'Found {len(http_resources)} HTTP resources loaded on HTTPS page',
                        'evidence': f'Examples: {", ".join(http_resources[:3])}',
                        'recommendation': 'Replace all HTTP resources with HTTPS versions or relative URLs.',
                        'cwe': 'CWE-311',
                        'references': 'https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content'
                    })

    # ==============================
    # A03:2021 – Injection
    # ==============================
    def _test_injection_vulnerabilities(self):
        """Test for SQL injection, XSS, and command injection"""
        print("[*] Testing A03: Injection Vulnerabilities...")
        
        resp = self._safe_get(self.base_url)
        if not resp:
            return
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # Test forms for SQL injection
        forms = soup.find_all('form')
        for form in forms[:5]:  # Test first 5 forms
            self._test_sql_injection(form)
            self._test_xss(form)
        
        # Test URL parameters for SQL injection
        links = soup.find_all('a', href=True)
        for link in links[:10]:
            href = link['href']
            if '?' in href and '=' in href:
                self._test_url_sql_injection(urljoin(self.base_url, href))

    def _test_sql_injection(self, form):
        """Test form for SQL injection"""
        action = form.get('action')
        method = form.get('method', 'get').lower()
        
        if not action:
            return
        
        url = urljoin(self.base_url, action)
        form_id = hashlib.md5(str(form).encode()).hexdigest()
        
        if form_id in self.forms_tested:
            return
        self.forms_tested.add(form_id)
        
        # SQL injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "1' OR '1'='1' --",
            "admin' --",
            "' OR 1=1--",
            "1' UNION SELECT NULL--"
        ]
        
        inputs = form.find_all(['input', 'textarea'])
        if not inputs:
            return
        
        for payload in sql_payloads:
            data = {}
            for input_tag in inputs:
                name = input_tag.get('name')
                if name:
                    input_type = input_tag.get('type', 'text')
                    if input_type not in ['submit', 'button', 'image']:
                        data[name] = payload
            
            if not data:
                continue
            
            try:
                if method == 'post':
                    resp = self._safe_post(url, data=data)
                else:
                    resp = self._safe_get(url, params=data)
                
                if resp and resp.status_code == 200:
                    # Check for SQL error messages
                    error_patterns = [
                        r'sql syntax.*mysql',
                        r'warning.*mysql',
                        r'unclosed quotation mark',
                        r'quoted string not properly terminated',
                        r'sql server.*error',
                        r'microsoft ole db provider for sql server',
                        r'invalid query',
                        r'ora-\d{5}',
                        r'postgresql.*error',
                        r'sqlite.*error'
                    ]
                    
                    content_lower = resp.text.lower()
                    for pattern in error_patterns:
                        if re.search(pattern, content_lower):
                            self.vulnerabilities.append({
                                'owasp_id': 'A03:2021',
                                'type': 'SQL Injection',
                                'severity': 'Critical',
                                'description': 'Potential SQL injection vulnerability detected',
                                'evidence': f'Form action: {url} | Payload: {payload} | Error pattern found',
                                'recommendation': 'Use parameterized queries (prepared statements), ORM frameworks, and input validation. Never concatenate user input into SQL queries.',
                                'cwe': 'CWE-89',
                                'references': 'https://owasp.org/www-community/attacks/SQL_Injection'
                            })
                            return
            except:
                pass

    def _test_url_sql_injection(self, url):
        """Test URL parameters for SQL injection"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return
        
        sql_payloads = ["'", "1' OR '1'='1", "1' AND '1'='2"]
        
        for param_name in list(params.keys())[:3]:
            for payload in sql_payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                
                resp = self._safe_get(test_url, params=test_params)
                
                if resp and resp.status_code == 500:
                    # Server error might indicate SQL injection
                    if any(err in resp.text.lower() for err in ['sql', 'mysql', 'syntax', 'database']):
                        self.vulnerabilities.append({
                            'owasp_id': 'A03:2021',
                            'type': 'SQL Injection (URL Parameter)',
                            'severity': 'Critical',
                            'description': f'URL parameter "{param_name}" vulnerable to SQL injection',
                            'evidence': f'URL: {test_url} | Param: {param_name} | Payload: {payload}',
                            'recommendation': 'Use parameterized queries and input validation for all URL parameters.',
                            'cwe': 'CWE-89',
                            'references': 'https://owasp.org/www-community/attacks/SQL_Injection'
                        })
                        return

    def _test_xss(self, form):
        """Test form for Cross-Site Scripting (XSS)"""
        action = form.get('action')
        method = form.get('method', 'get').lower()
        
        if not action:
            return
        
        url = urljoin(self.base_url, action)
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg/onload=alert('XSS')>"
        ]
        
        inputs = form.find_all(['input', 'textarea'])
        
        for payload in xss_payloads[:2]:  # Test 2 payloads
            data = {}
            for input_tag in inputs:
                name = input_tag.get('name')
                if name:
                    input_type = input_tag.get('type', 'text')
                    if input_type not in ['submit', 'button', 'image', 'password']:
                        data[name] = payload
            
            if not data:
                continue
            
            try:
                if method == 'post':
                    resp = self._safe_post(url, data=data)
                else:
                    resp = self._safe_get(url, params=data)
                
                if resp and resp.status_code == 200:
                    # Check if payload is reflected without encoding
                    if payload in resp.text:
                        self.vulnerabilities.append({
                            'owasp_id': 'A03:2021',
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'High',
                            'description': 'Reflected XSS vulnerability detected - user input not properly sanitized',
                            'evidence': f'Form action: {url} | Payload reflected: {payload[:50]}',
                            'recommendation': 'Implement output encoding, Content Security Policy (CSP), and use frameworks with auto-escaping.',
                            'cwe': 'CWE-79',
                            'references': 'https://owasp.org/www-community/attacks/xss/'
                        })
                        return
            except:
                pass

    # ==============================
    # A04:2021 – Insecure Design
    # ==============================
    def _test_insecure_design(self):
        """Test for insecure design patterns"""
        print("[*] Testing A04: Insecure Design...")
        
        resp = self._safe_get(self.base_url)
        if not resp:
            return
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            # Check for CSRF protection
            csrf_token = form.find('input', {'name': re.compile(r'csrf|token|_token|authenticity', re.I)})
            
            if not csrf_token and form.get('method', '').lower() == 'post':
                action = form.get('action', 'unknown')
                self.vulnerabilities.append({
                    'owasp_id': 'A04:2021',
                    'type': 'Missing CSRF Protection',
                    'severity': 'High',
                    'description': 'Form submits without CSRF token protection',
                    'evidence': f'Form action: {action}',
                    'recommendation': 'Implement anti-CSRF tokens for all state-changing operations. Use SameSite cookie attribute.',
                    'cwe': 'CWE-352',
                    'references': 'https://owasp.org/www-community/attacks/csrf'
                })

    # ==============================
    # A05:2021 – Security Misconfiguration
    # ==============================
    def _test_security_misconfiguration(self):
        """Test for security misconfigurations"""
        print("[*] Testing A05: Security Misconfiguration...")
        
        resp = self._safe_get(self.base_url)
        if not resp:
            return
        
        headers = {k.lower(): v for k, v in resp.headers.items()}
        
        # Critical security headers
        critical_headers = {
            'content-security-policy': {
                'severity': 'High',
                'recommendation': "Implement CSP: Content-Security-Policy: default-src 'self'; script-src 'self'"
            },
            'x-frame-options': {
                'severity': 'Medium',
                'recommendation': 'Add header: X-Frame-Options: DENY or SAMEORIGIN'
            },
            'x-content-type-options': {
                'severity': 'Medium',
                'recommendation': 'Add header: X-Content-Type-Options: nosniff'
            }
        }
        
        for header, info in critical_headers.items():
            if header not in headers:
                self.vulnerabilities.append({
                    'owasp_id': 'A05:2021',
                    'type': f'Missing Security Header: {header.upper()}',
                    'severity': info['severity'],
                    'description': f'Security header {header} not configured',
                    'evidence': 'Header not present in HTTP response',
                    'recommendation': info['recommendation'],
                    'cwe': 'CWE-16',
                    'references': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
                })
        
        # Check for information disclosure
        server_header = headers.get('server', '')
        if server_header and len(server_header) > 10:
            self.vulnerabilities.append({
                'owasp_id': 'A05:2021',
                'type': 'Server Version Disclosure',
                'severity': 'Low',
                'description': 'Server header reveals technology and version',
                'evidence': f'Server: {server_header}',
                'recommendation': 'Remove or obfuscate Server header to prevent fingerprinting.',
                'cwe': 'CWE-200',
                'references': 'https://owasp.org/www-community/Security_Headers'
            })
        
        # Check for exposed sensitive files
        sensitive_files = [
            '.git/config',
            '.env',
            'config.php.bak',
            'web.config',
            '.htaccess',
            'composer.json',
            'package.json'
        ]
        
        exposed_files = []
        for file in sensitive_files:
            url = urljoin(self.base_url + '/', file)
            resp = self._safe_get(url, allow_redirects=False)
            if resp and resp.status_code == 200 and len(resp.text) > 10:
                exposed_files.append(file)
        
        if exposed_files:
            self.vulnerabilities.append({
                'owasp_id': 'A05:2021',
                'type': 'Exposed Sensitive Files',
                'severity': 'High',
                'description': 'Configuration files accessible publicly',
                'evidence': f'Exposed files: {", ".join(exposed_files)}',
                'recommendation': 'Block access to sensitive files via web server configuration. Use .htaccess or nginx rules.',
                'cwe': 'CWE-552',
                'references': 'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload'
            })

    # ==============================
    # A06:2021 – Vulnerable Components
    # ==============================
    def _test_outdated_components(self):
        """Test for vulnerable and outdated components"""
        print("[*] Testing A06: Vulnerable and Outdated Components...")
        
        resp = self._safe_get(self.base_url)
        if not resp:
            return
        
        # Check for common vulnerable endpoints
        wordpress_check = self._safe_get(urljoin(self.base_url, '/wp-includes/version.php'))
        if wordpress_check and wordpress_check.status_code == 200:
            version_match = re.search(r"\$wp_version = '([^']+)'", wordpress_check.text)
            if version_match:
                version = version_match.group(1)
                self.vulnerabilities.append({
                    'owasp_id': 'A06:2021',
                    'type': 'WordPress Version Disclosure',
                    'severity': 'Medium',
                    'description': f'WordPress version {version} detected',
                    'evidence': f'Version file accessible: /wp-includes/version.php',
                    'recommendation': 'Update WordPress to latest version and remove version disclosure. Check for known vulnerabilities.',
                    'cwe': 'CWE-1104',
                    'references': 'https://wpvulndb.com/'
                })
        
        # Check for outdated jQuery
        soup = BeautifulSoup(resp.text, 'html.parser')
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script.get('src', '')
            jquery_match = re.search(r'jquery[.-](\d+\.\d+\.\d+)', src.lower())
            if jquery_match:
                version = jquery_match.group(1)
                major_version = int(version.split('.')[0])
                if major_version < 3:
                    self.vulnerabilities.append({
                        'owasp_id': 'A06:2021',
                        'type': 'Outdated jQuery Library',
                        'severity': 'Medium',
                        'description': f'jQuery version {version} has known vulnerabilities',
                        'evidence': f'Script source: {src}',
                        'recommendation': 'Update jQuery to version 3.6.0 or later.',
                        'cwe': 'CWE-1104',
                        'references': 'https://snyk.io/vuln/npm:jquery'
                    })
                    break

    # ==============================
    # A07:2021 – Authentication Failures
    # ==============================
    def _test_authentication_failures(self):
        """Test for authentication and session management issues"""
        print("[*] Testing A07: Identification and Authentication Failures...")
        
        resp = self._safe_get(self.base_url)
        if not resp:
            return
        
        # Check cookie security
        if resp.cookies:
            for cookie in resp.cookies:
                issues = []
                
                if not cookie.secure and self.base_url.startswith('https://'):
                    issues.append('Missing Secure flag')
                
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append('Missing HttpOnly flag')
                
                if not cookie.has_nonstandard_attr('SameSite'):
                    issues.append('Missing SameSite attribute')
                
                if issues and 'session' in cookie.name.lower():
                    self.vulnerabilities.append({
                        'owasp_id': 'A07:2021',
                        'type': 'Insecure Session Cookie',
                        'severity': 'High',
                        'description': f'Session cookie "{cookie.name}" lacks security attributes',
                        'evidence': f'Issues: {", ".join(issues)}',
                        'recommendation': 'Set Secure, HttpOnly, and SameSite=Strict attributes for session cookies.',
                        'cwe': 'CWE-614',
                        'references': 'https://owasp.org/www-community/controls/SecureCookieAttribute'
                    })
        
        # Check for weak password policies (if login form present)
        soup = BeautifulSoup(resp.text, 'html.parser')
        password_fields = soup.find_all('input', {'type': 'password'})
        
        for pwd_field in password_fields:
            # Check for password requirements
            form = pwd_field.find_parent('form')
            if form:
                # Look for password strength indicators
                min_length = pwd_field.get('minlength')
                pattern = pwd_field.get('pattern')
                
                if not min_length and not pattern:
                    self.vulnerabilities.append({
                        'owasp_id': 'A07:2021',
                        'type': 'Weak Password Policy',
                        'severity': 'Medium',
                        'description': 'No client-side password requirements enforced',
                        'evidence': 'Password field has no minlength or pattern attribute',
                        'recommendation': 'Enforce strong passwords: minimum 12 characters, complexity requirements, and check against breach databases.',
                        'cwe': 'CWE-521',
                        'references': 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'
                    })
                    break

    # ==============================
    # A08:2021 – Integrity Failures
    # ==============================
    def _test_integrity_failures(self):
        """Test for software and data integrity failures"""
        print("[*] Testing A08: Software and Data Integrity Failures...")
        
        resp = self._safe_get(self.base_url)
        if not resp:
            return
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # Check for SRI on external scripts
        external_scripts = []
        scripts = soup.find_all('script', src=True)
        
        for script in scripts:
            src = script.get('src', '')
            if src.startswith(('http://', 'https://', '//')):
                if not script.get('integrity'):
                    external_scripts.append(src)
        
        if external_scripts and len(external_scripts) > 0:
            self.vulnerabilities.append({
                'owasp_id': 'A08:2021',
                'type': 'Missing Subresource Integrity (SRI)',
                'severity': 'Medium',
                'description': f'External scripts loaded without integrity checks ({len(external_scripts)} found)',
                'evidence': f'Scripts without SRI: {", ".join(external_scripts[:3])}',
                'recommendation': 'Add integrity and crossorigin attributes to external scripts and stylesheets.',
                'cwe': 'CWE-353',
                'references': 'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity'
            })

    # ==============================
    # A09:2021 – Logging Failures
    # ==============================
    def _test_logging_monitoring(self):
        """Test for security logging and monitoring failures"""
        print("[*] Testing A09: Security Logging and Monitoring Failures...")
        
        # Test for verbose error messages
        test_urls = [
            urljoin(self.base_url, '/nonexistent-page-12345'),
            urljoin(self.base_url, '/error.php'),
            urljoin(self.base_url, '/?id=invalid')
        ]
        
        for url in test_urls:
            resp = self._safe_get(url)
            if resp and resp.status_code in [404, 500]:
                error_indicators = [
                    'stack trace',
                    'line number',
                    'file path',
                    'exception',
                    'error at',
                    'warning:',
                    'fatal error',
                    'mysql_',
                    'mysqli_',
                    'pg_query',
                    'sqlite3'
                ]
                
                content_lower = resp.text.lower()
                found_indicators = [ind for ind in error_indicators if ind in content_lower]
                
                if found_indicators:
                    self.vulnerabilities.append({
                        'owasp_id': 'A09:2021',
                        'type': 'Verbose Error Messages',
                        'severity': 'Medium',
                        'description': 'Detailed error messages expose system information',
                        'evidence': f'Error indicators found: {", ".join(found_indicators[:3])}',
                        'recommendation': 'Implement custom error pages, disable debug mode in production, and log errors server-side only.',
                        'cwe': 'CWE-209',
                        'references': 'https://owasp.org/www-community/Improper_Error_Handling'
                    })
                    break

    # ==============================
    # A10:2021 – SSRF
    # ==============================
    def _test_ssrf(self):
        """Test for Server-Side Request Forgery"""
        print("[*] Testing A10: Server-Side Request Forgery (SSRF)...")
        
        resp = self._safe_get(self.base_url)
        if not resp:
            return
        
        # Look for URL parameters that might be vulnerable
        soup = BeautifulSoup(resp.text, 'html.parser')
        links = soup.find_all('a', href=True)
        
        ssrf_params = ['url', 'uri', 'path', 'dest', 'redirect', 'link', 'fetch', 'file', 'download']
        
        for link in links[:10]:
            href = link['href']
            if '?' in href and '=' in href:
                parsed = urlparse(href)
                params = parse_qs(parsed.query)
                
                for param_name in params.keys():
                    if any(ssrf_param in param_name.lower() for ssrf_param in ssrf_params):
                        # Test with internal IP
                        test_params = params.copy()
                        test_params[param_name] = ['http://127.0.0.1']
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        
                        test_resp = self._safe_get(test_url, params=test_params)
                        if test_resp and test_resp.status_code == 200:
                            self.vulnerabilities.append({
                                'owasp_id': 'A10:2021',
                                'type': 'Potential SSRF Vulnerability',
                                'severity': 'High',
                                'description': f'Parameter "{param_name}" may be vulnerable to SSRF attacks',
                                'evidence': f'URL parameter accepts URLs: {urljoin(self.base_url, href)}',
                                'recommendation': 'Validate and sanitize URL inputs, use allowlists for domains, and implement network segmentation.',
                                'cwe': 'CWE-918',
                                'references': 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/'
                            })
                            return


# ==============================
# NMAP SCANNER (Enhanced)
# ==============================
class NmapScanner:
    def __init__(self):
        if shutil.which("nmap") is None:
            raise EnvironmentError("Nmap executable not found in PATH.")

    def _run_nmap_command(self, cmd_args):
        try:
            proc = subprocess.run(cmd_args, capture_output=True, text=True, check=True, timeout=600)
            return proc.stdout
        except subprocess.CalledProcessError:
            return None
        except subprocess.TimeoutExpired:
            return None

    def scan_vulnerabilities(self, target, ports=None, scan_type="-sV"):
        """Enhanced vulnerability scanning with CVE detection"""
        cmd = ["nmap", scan_type, "--script", "vuln", "-oX", "-", "-Pn"]
        if ports:
            cmd.extend(["-p", ports])
        cmd.append(target)
        xml_output = self._run_nmap_command(cmd)
        if not xml_output:
            return []
        return self._parse_vuln_xml(xml_output)

    def _parse_vuln_xml(self, xml_text):
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_text)
        findings = []
        
        for host in root.findall("host"):
            addr_elem = host.find("address")
            addr = addr_elem.get("addr") if addr_elem is not None else "unknown"
            ports_element = host.find("ports")
            
            if not ports_element:
                continue
            
            for port in ports_element.findall("port"):
                portid = port.get("portid")
                proto = port.get("protocol")
                service = port.find("service")
                service_name = service.get("name") if service is not None else "unknown"
                
                for script in port.findall("script"):
                    script_id = script.get("id")
                    output = script.get("output", "").strip()
                    
                    if not script_id or not output:
                        continue
                    
                    # Extract CVEs
                    cves = re.findall(r"\bCVE-\d{4}-\d{4,7}\b", output, flags=re.IGNORECASE)
                    
                    # Determine severity based on script output
                    severity = "Medium"
                    if any(keyword in output.lower() for keyword in ['critical', 'exploit', 'remote code execution', 'rce']):
                        severity = "Critical"
                    elif any(keyword in output.lower() for keyword in ['high', 'vulnerable', 'injection']):
                        severity = "High"
                    elif 'cve' in output.lower():
                        severity = "High"
                    
                    findings.append({
                        "type": f"Port {portid}/{proto} - {service_name}",
                        "severity": severity,
                        "description": f"Vulnerability detected: {script_id}",
                        "evidence": output[:300],
                        "host": addr,
                        "port": portid,
                        "proto": proto,
                        "script_id": script_id,
                        "cves": cves,
                        "recommendation": self._get_recommendation(script_id, cves)
                    })
        
        return findings
    
    def _get_recommendation(self, script_id, cves):
        """Get specific recommendations based on vulnerability"""
        recommendations = {
            'http-csrf': 'Implement CSRF tokens for all state-changing operations',
            'http-sql-injection': 'Use parameterized queries and input validation',
            'http-stored-xss': 'Implement output encoding and Content Security Policy',
            'http-vuln-cve': 'Update the affected software to the latest patched version',
            'ssl-poodle': 'Disable SSLv3 and use TLS 1.2 or higher',
            'ssl-heartbleed': 'Update OpenSSL to version 1.0.1g or later',
            'smb-vuln-ms17-010': 'Apply Microsoft security patch MS17-010 immediately'
        }
        
        if cves:
            return f"Patch CVEs: {', '.join(cves)}. Check NVD for details."
        
        return recommendations.get(script_id, 'Update software and follow vendor security advisories')


# ==============================
# VIRUSTOTAL SCANNER (Keep as is)
# ==============================
class VirusTotalScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}

    def scan_file(self, file_path):
        """Upload and scan a file"""
        if not os.path.exists(file_path):
            return {"error": "File not found"}
        
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}

        try:
            file_hash = self._calculate_file_hash(file_path)
            existing_report = self._get_file_report(file_hash)
            
            if existing_report and 'data' in existing_report:
                return self._parse_file_report(existing_report)
            
            with open(file_path, 'rb') as f:
                files = {'file': f}
                response = requests.post(
                    f"{self.base_url}/files",
                    headers=self.headers,
                    files=files,
                    timeout=60
                )
            
            if response.status_code == 200:
                result = response.json()
                analysis_id = result.get('data', {}).get('id')
                time.sleep(15)
                return self._get_analysis_results(analysis_id)
            else:
                return {"error": f"Upload failed: {response.status_code}"}
                
        except Exception as e:
            return {"error": str(e)}

    def scan_url(self, url):
        """Scan a URL with VirusTotal"""
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}

        try:
            data = {"url": url}
            response = requests.post(
                f"{self.base_url}/urls",
                headers=self.headers,
                data=data,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                analysis_id = result.get('data', {}).get('id')
                time.sleep(15)
                return self._get_analysis_results(analysis_id)
            else:
                return {"error": f"URL scan failed: {response.status_code}"}
                
        except Exception as e:
            return {"error": str(e)}

    def _calculate_file_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _get_file_report(self, file_hash):
        try:
            response = requests.get(
                f"{self.base_url}/files/{file_hash}",
                headers=self.headers,
                timeout=30
            )
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return None

    def _get_analysis_results(self, analysis_id):
        try:
            response = requests.get(
                f"{self.base_url}/analyses/{analysis_id}",
                headers=self.headers,
                timeout=30
            )
            if response.status_code == 200:
                return self._parse_file_report(response.json())
        except Exception as e:
            return {"error": str(e)}
        return {"error": "Analysis retrieval failed"}

    def _parse_file_report(self, report):
        try:
            attributes = report.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            results = attributes.get('last_analysis_results', {})
            
            detections = []
            for engine, result in results.items():
                if result.get('category') in ['malicious', 'suspicious']:
                    detections.append({
                        'engine': engine,
                        'result': result.get('result', 'Unknown'),
                        'category': result.get('category')
                    })
            
            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0),
                'total_scans': sum(stats.values()),
                'detections': detections[:10]
            }
        except Exception as e:
            return {"error": f"Parse error: {str(e)}"}


# ==============================
# SEVERITY AND SCORING
# ==============================
def classify_severity(vuln):
    """Classify vulnerability severity"""
    if isinstance(vuln, dict):
        return vuln.get('severity', 'Low')
    
    t = str(vuln).lower()
    if any(k in t for k in ["critical", "exploitable", "rce", "sql injection", "directory traversal"]):
        return "Critical"
    if any(k in t for k in ["high", "xss", "csrf", "authentication"]):
        return "High"
    if any(k in t for k in ["medium", "missing", "weak", "disclosure"]):
        return "Medium"
    return "Low"

def compute_score(findings):
    """Compute security score based on findings"""
    weights = {"Critical": 40, "High": 25, "Medium": 12, "Low": 4}
    raw_score = sum(weights.get(classify_severity(f), 0) for f in findings)
    return max(0, 100 - min(raw_score, 100))


# ==============================
# ENHANCED PDF REPORT
# ==============================
def generate_pdf(target, findings, score, filename, scan_type=""):
    """Generate comprehensive PDF report with enhanced formatting"""
    os.makedirs('app/static/reports', exist_ok=True)
    filepath = os.path.join('app/static/reports', filename)

    doc = SimpleDocTemplate(
        filepath, 
        pagesize=A4,
        rightMargin=20*mm,
        leftMargin=20*mm,
        topMargin=20*mm,
        bottomMargin=20*mm
    )
    styles = getSampleStyleSheet()
    story = []
    
    # Custom styles
    title_style = styles["Title"]
    title_style.textColor = colors.HexColor("#4F46E5")
    title_style.fontSize = 24
    title_style.spaceAfter = 20
    
    heading_style = styles["Heading2"]
    heading_style.textColor = colors.HexColor("#1F2937")
    heading_style.fontSize = 16
    heading_style.spaceAfter = 12
    
    # Create custom styles for severity levels
    from reportlab.lib.styles import ParagraphStyle
    
    critical_style = ParagraphStyle(
        'Critical',
        parent=styles['Normal'],
        textColor=colors.HexColor("#DC2626"),
        fontSize=10,
        leftIndent=10
    )
    
    high_style = ParagraphStyle(
        'High',
        parent=styles['Normal'],
        textColor=colors.HexColor("#EA580C"),
        fontSize=10,
        leftIndent=10
    )
    
    medium_style = ParagraphStyle(
        'Medium',
        parent=styles['Normal'],
        textColor=colors.HexColor("#D97706"),
        fontSize=10,
        leftIndent=10
    )
    
    low_style = ParagraphStyle(
        'Low',
        parent=styles['Normal'],
        textColor=colors.HexColor("#2563EB"),
        fontSize=10,
        leftIndent=10
    )

    # Title
    story.append(Paragraph("<b>Cyber Hygiene Analysis Report</b>", title_style))
    story.append(Spacer(1, 8))
    
    # Metadata box
    metadata_data = [
        ["Target:", target],
        ["Scan Type:", scan_type],
        ["Generated:", datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')]
    ]
    metadata_table = Table(metadata_data, colWidths=[40*mm, 130*mm])
    metadata_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F3F4F6")),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor("#374151")),
        ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor("#1F2937")),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#D1D5DB"))
    ]))
    story.append(metadata_table)
    story.append(Spacer(1, 20))
    
    # Security Score with visual bar
    score_color = colors.HexColor("#10B981") if score >= 80 else colors.HexColor("#F59E0B") if score >= 60 else colors.HexColor("#EF4444")
    story.append(Paragraph(f"<b>Overall Security Score</b>", heading_style))
    
    score_data = [[f"{score}/100"]]
    score_table = Table(score_data, colWidths=[170*mm])
    score_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), score_color),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 32),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING', (0, 0), (-1, -1), 20),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 20),
    ]))
    story.append(score_table)
    
    # Score interpretation
    if score >= 80:
        interpretation = "Excellent - Minimal security issues detected"
    elif score >= 60:
        interpretation = "Moderate - Some security improvements recommended"
    elif score >= 40:
        interpretation = "Poor - Multiple vulnerabilities require attention"
    else:
        interpretation = "Critical - Immediate action required"
    
    story.append(Paragraph(f"<i>{interpretation}</i>", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # Summary Statistics
    critical = sum(1 for f in findings if classify_severity(f) == "Critical")
    high = sum(1 for f in findings if classify_severity(f) == "High")
    medium = sum(1 for f in findings if classify_severity(f) == "Medium")
    low = sum(1 for f in findings if classify_severity(f) == "Low")
    
    story.append(Paragraph(f"<b>Vulnerability Summary</b>", heading_style))
    
    summary_data = [
        ["[CRITICAL]", "Critical", str(critical)],
        ["[HIGH]", "High", str(high)],
        ["[MEDIUM]", "Medium", str(medium)],
        ["[LOW]", "Low", str(low)],
        ["[TOTAL]", "Total", str(len(findings))]
    ]
    
    summary_table = Table(summary_data, colWidths=[25*mm, 125*mm, 20*mm])
    summary_table.setStyle(TableStyle([
        # Background colors for severity levels
        ('BACKGROUND', (0, 0), (0, 0), colors.HexColor("#DC2626")),
        ('BACKGROUND', (0, 1), (0, 1), colors.HexColor("#EA580C")),
        ('BACKGROUND', (0, 2), (0, 2), colors.HexColor("#D97706")),
        ('BACKGROUND', (0, 3), (0, 3), colors.HexColor("#2563EB")),
        ('BACKGROUND', (0, 4), (0, 4), colors.HexColor("#6B7280")),
        
        # Row backgrounds
        ('BACKGROUND', (1, 0), (-1, 0), colors.HexColor("#FEE2E2")),
        ('BACKGROUND', (1, 1), (-1, 1), colors.HexColor("#FFEDD5")),
        ('BACKGROUND', (1, 2), (-1, 2), colors.HexColor("#FEF3C7")),
        ('BACKGROUND', (1, 3), (-1, 3), colors.HexColor("#DBEAFE")),
        ('BACKGROUND', (1, 4), (-1, 4), colors.HexColor("#F3F4F6")),
        
        # Text colors
        ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (0, -1), 8),
        ('FONTSIZE', (1, 0), (-1, -1), 11),
        ('PADDING', (0, 0), (-1, -1), 10),
        ('ALIGN', (0, 0), (0, -1), 'CENTER'),
        ('ALIGN', (2, 0), (2, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB"))
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))
    
    # Detailed Findings
    story.append(Paragraph("<b>Detailed Findings</b>", heading_style))
    story.append(Spacer(1, 10))
    
    if not findings:
        story.append(Paragraph(
            "<b>[✓] No vulnerabilities detected!</b> Your target appears to have good security hygiene.",
            styles['Normal']
        ))
    else:
        for i, f in enumerate(findings, 1):
            # Extract finding data
            if isinstance(f, dict):
                severity = f.get('severity', 'Low')
                vuln_type = f.get('type', 'Unknown')
                description = f.get('description', 'No description provided')
                recommendation = f.get('recommendation', 'N/A')
                evidence = f.get('evidence', '')
                owasp_id = f.get('owasp_id', '')
                cwe = f.get('cwe', '')
                references = f.get('references', '')
            elif isinstance(f, tuple):
                severity = classify_severity(f)
                vuln_type = str(f[0])
                description = str(f[2]) if len(f) > 2 else ''
                recommendation = "Review and remediate"
                evidence = ''
                owasp_id = ''
                cwe = ''
                references = ''
            else:
                severity = "Info"
                vuln_type = "Finding"
                description = str(f)
                recommendation = "Review"
                evidence = ''
                owasp_id = ''
                cwe = ''
                references = ''
            
            # Severity configuration with text-based icons
            severity_config = {
                'Critical': {'label': '[CRITICAL]', 'bg': colors.HexColor("#FEE2E2"), 'text': colors.HexColor("#991B1B"), 'badge_bg': colors.HexColor("#DC2626")},
                'High': {'label': '[HIGH]', 'bg': colors.HexColor("#FFEDD5"), 'text': colors.HexColor("#9A3412"), 'badge_bg': colors.HexColor("#EA580C")},
                'Medium': {'label': '[MEDIUM]', 'bg': colors.HexColor("#FEF3C7"), 'text': colors.HexColor("#92400E"), 'badge_bg': colors.HexColor("#D97706")},
                'Low': {'label': '[LOW]', 'bg': colors.HexColor("#DBEAFE"), 'text': colors.HexColor("#1E40AF"), 'badge_bg': colors.HexColor("#2563EB")},
                'Info': {'label': '[INFO]', 'bg': colors.HexColor("#F3F4F6"), 'text': colors.HexColor("#374151"), 'badge_bg': colors.HexColor("#6B7280")},
                'Error': {'label': '[ERROR]', 'bg': colors.HexColor("#FEE2E2"), 'text': colors.HexColor("#991B1B"), 'badge_bg': colors.HexColor("#DC2626")}
            }
            config = severity_config.get(severity, severity_config['Info'])
            
            # Finding header with severity badge
            header_data = [[config['label'], f"Finding #{i}: {vuln_type}"]]
            header_table = Table(header_data, colWidths=[25*mm, 145*mm])
            header_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, 0), config['badge_bg']),
                ('BACKGROUND', (1, 0), (1, 0), config['bg']),
                ('TEXTCOLOR', (0, 0), (0, 0), colors.white),
                ('TEXTCOLOR', (1, 0), (1, 0), config['text']),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (0, 0), 9),
                ('FONTSIZE', (1, 0), (1, 0), 12),
                ('ALIGN', (0, 0), (0, 0), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('PADDING', (0, 0), (-1, -1), 8),
                ('BOX', (0, 0), (-1, -1), 2, config['text'])
            ]))
            story.append(header_table)
            story.append(Spacer(1, 5))
            
            # Finding details in a styled box
            finding_content = []
            
            # Severity and tags
            tags = f"<b>Severity:</b> {severity}"
            if owasp_id:
                tags += f" | <b>OWASP:</b> {owasp_id}"
            if cwe:
                tags += f" | <b>CWE:</b> {cwe}"
            finding_content.append([Paragraph(tags, styles['Normal'])])
            
            # Description
            finding_content.append([Paragraph(f"<b>Description:</b><br/>{description[:500]}", styles['Normal'])])
            
            # Evidence (if available)
            if evidence:
                evidence_text = evidence[:300] + "..." if len(evidence) > 300 else evidence
                # Escape HTML in evidence
                evidence_text = evidence_text.replace('<', '&lt;').replace('>', '&gt;')
                finding_content.append([Paragraph(f"<b>Evidence:</b><br/><font name='Courier' size='8'>{evidence_text}</font>", styles['Normal'])])
            
            # Recommendation
            if recommendation and recommendation != 'N/A':
                finding_content.append([Paragraph(f"<b>[!] Recommendation:</b><br/>{recommendation[:400]}", styles['Normal'])])
            
            # References
            if references:
                finding_content.append([Paragraph(f"<b>References:</b><br/><font size='8'>{references}</font>", styles['Normal'])])
            
            finding_table = Table(finding_content, colWidths=[170*mm])
            finding_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), config['bg']),
                ('TEXTCOLOR', (0, 0), (-1, -1), config['text']),
                ('PADDING', (0, 0), (-1, -1), 10),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOX', (0, 0), (-1, -1), 1, config['text']),
                ('LEFTPADDING', (0, 0), (-1, -1), 15),
                ('RIGHTPADDING', (0, 0), (-1, -1), 15),
            ]))
            story.append(finding_table)
            story.append(Spacer(1, 15))
    
    # Footer with recommendations
    story.append(Spacer(1, 20))
    story.append(Paragraph("<b>General Recommendations</b>", heading_style))
    
    recommendations = [
        "[1] Address all Critical and High severity vulnerabilities immediately",
        "[2] Implement regular security scanning as part of your CI/CD pipeline",
        "[3] Keep all software components and dependencies up to date",
        "[4] Follow OWASP Top 10 best practices for secure development",
        "[5] Conduct regular security audits and penetration testing",
        "[6] Implement security monitoring and logging for all applications"
    ]
    
    for rec in recommendations:
        story.append(Paragraph(rec, styles['Normal']))
        story.append(Spacer(1, 4))
    
    story.append(Spacer(1, 20))
    story.append(Paragraph(
        "<i>This report was generated by OWASP Security Scanner. For questions or support, consult your security team.</i>",
        styles['Normal']
    ))
    
    # Build PDF
    try:
        doc.build(story)
        return filename
    except Exception as e:
        print(f"PDF generation error: {e}")
        return None
# ==============================
# MAIN SCAN FUNCTION
# ==============================
def run_scan(target, scan_types, file_path=None):
    """
    Run comprehensive security scan
    
    Args:
        target: Target URL or IP
        scan_types: List of scan types ['owasp', 'nmap', 'virustotal_url', 'virustotal_file']
        file_path: Path to file for VirusTotal scanning
    """
    findings = []
    scan_type_name = ", ".join(scan_types)
    
    print(f"\n[*] Starting security scan for: {target}")
    print(f"[*] Scan types: {scan_type_name}\n")

    # OWASP Top 10 Scan
    if 'owasp' in scan_types or 'webscan' in scan_types or 'deepscan' in scan_types:
        try:
            print("[*] Running OWASP Top 10 vulnerability scan...")
            scanner = OWASPScanner(target)
            result = scanner.comprehensive_scan()
            findings.extend(result['vulnerabilities'])
            print(f"[+] OWASP scan complete: {len(result['vulnerabilities'])} vulnerabilities found")
        except Exception as e:
            findings.append({
                "type": "OWASP Scan Error",
                "severity": "Error",
                "description": str(e),
                "recommendation": "Check target accessibility and try again"
            })
            print(f"[-] OWASP scan error: {e}")

    # Nmap Vulnerability Scan
    if 'nmap' in scan_types:
        try:
            print("[*] Running Nmap vulnerability scan...")
            ns = NmapScanner()
            nmap_findings = ns.scan_vulnerabilities(target)
            findings.extend(nmap_findings)
            print(f"[+] Nmap scan complete: {len(nmap_findings)} findings")
        except Exception as e:
            findings.append({
                "type": "Nmap Scan Error",
                "severity": "Error",
                "description": str(e),
                "recommendation": "Ensure Nmap is installed"
            })
            print(f"[-] Nmap scan error: {e}")

    # VirusTotal URL Scan
    if 'virustotal_url' in scan_types:
        try:
            print("[*] Running VirusTotal URL scan...")
            vt = VirusTotalScanner(VIRUSTOTAL_API_KEY)
            result = vt.scan_url(target)
            if 'error' not in result:
                severity = "Critical" if result.get('malicious', 0) > 5 else "High" if result.get('malicious', 0) > 0 else "Info"
                findings.append({
                    "type": "VirusTotal URL Reputation",
                    "severity": severity,
                    "description": f"Malicious detections: {result.get('malicious', 0)}/{result.get('total_scans', 0)} | Suspicious: {result.get('suspicious', 0)}",
                    "recommendation": "Review detections and investigate flagged issues" if result.get('malicious', 0) > 0 else "URL appears clean",
                    "detail": result
                })
                print(f"[+] VirusTotal URL scan complete")
            else:
                findings.append({
                    "type": "VirusTotal URL Error",
                    "severity": "Error",
                    "description": result['error'],
                    "recommendation": "Check API key configuration"
                })
        except Exception as e:
            print(f"[-] VirusTotal URL scan error: {e}")

    # VirusTotal File Scan
    if 'virustotal_file' in scan_types and file_path:
        try:
            print("[*] Running VirusTotal file scan...")
            vt = VirusTotalScanner(VIRUSTOTAL_API_KEY)
            result = vt.scan_file(file_path)
            if 'error' not in result:
                severity = "Critical" if result.get('malicious', 0) > 5 else "High" if result.get('malicious', 0) > 0 else "Info"
                findings.append({
                    "type": "VirusTotal File Analysis",
                    "severity": severity,
                    "description": f"File: {os.path.basename(file_path)} | Malicious: {result.get('malicious', 0)}/{result.get('total_scans', 0)}",
                    "recommendation": "Quarantine file immediately" if result.get('malicious', 0) > 0 else "File appears safe",
                    "detail": result
                })
                print(f"[+] VirusTotal file scan complete")
            else:
                findings.append({
                    "type": "VirusTotal File Error",
                    "severity": "Error",
                    "description": result['error'],
                    "recommendation": "Check file path and API key"
                })
        except Exception as e:
            print(f"[-] VirusTotal file scan error: {e}")

    # Calculate security score
    score = compute_score(findings)
    
    # Generate PDF report
    pdf_filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    try:
        generate_pdf(target, findings, score, pdf_filename, scan_type_name)
        print(f"\n[+] PDF report generated: {pdf_filename}")
    except Exception as e:
        pdf_filename = None
        print(f"[-] PDF generation error: {e}")

    print(f"\n[*] Scan complete!")
    print(f"[*] Security Score: {score}/100")
    print(f"[*] Total Vulnerabilities: {len(findings)}")
    
    # Format findings for return
    formatted_findings = []
    for f in findings:
        if isinstance(f, dict):
            formatted_findings.append({
                'owasp_id': f.get('owasp_id', ''),
                'type': f.get('type', 'Unknown'),
                'severity': f.get('severity', 'Low'),
                'description': f.get('description', ''),
                'evidence': f.get('evidence', ''),
                'recommendation': f.get('recommendation', 'N/A'),
                'cwe': f.get('cwe', ''),
                'references': f.get('references', ''),
                'detail': f.get('detail')
            })
        elif isinstance(f, tuple):
            formatted_findings.append({
                'type': f[0],
                'severity': classify_severity(f),
                'description': str(f[2]) if len(f) > 2 else '',
                'recommendation': 'Review and remediate'
            })

    return {
        'findings': formatted_findings,
        'score': score,
        'pdf_path': pdf_filename,
        'summary': {
            'total': len(findings),
            'critical': sum(1 for f in findings if classify_severity(f) == 'Critical'),
            'high': sum(1 for f in findings if classify_severity(f) == 'High'),
            'medium': sum(1 for f in findings if classify_severity(f) == 'Medium'),
            'low': sum(1 for f in findings if classify_severity(f) == 'Low')
        }
    }


# ==============================
# EXAMPLE USAGE
# ==============================
if __name__ == "__main__":
    # Example usage
    target_url = "https://example.com"
    scan_types = ['owasp']  # or ['owasp', 'nmap', 'virustotal_url']
    
    results = run_scan(target_url, scan_types)
    
    print("\n" + "="*60)
    print("SCAN RESULTS SUMMARY")
    print("="*60)
    print(f"Target: {target_url}")
    print(f"Security Score: {results['score']}/100")
    print(f"\nVulnerabilities Found: {results['summary']['total']}")
    print(f"  - Critical: {results['summary']['critical']}")
    print(f"  - High: {results['summary']['high']}")
    print(f"  - Medium: {results['summary']['medium']}")
    print(f"  - Low: {results['summary']['low']}")
    
    if results['pdf_path']:
        print(f"\nPDF Report: {results['pdf_path']}")
    
    print("\n" + "="*60)