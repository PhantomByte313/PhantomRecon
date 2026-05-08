"""
core/scanner.py
===============
Phantom Recon — Core Scanning Engine

All scanning modules run in background QThreads and emit results
via Qt signals so the UI stays responsive.

Modules:
  - DNSScanner       : Full DNS enumeration + zone transfer
  - PortScanner      : TCP port scanning with banner grabbing
  - WHOISScanner     : Domain registration info
  - SSLScanner       : Certificate analysis
  - WebScanner       : Technology detection, headers, links
  - GeoScanner       : IP geolocation + ASN
  - SubdomainScanner : Brute-force + passive subdomain enum
  - ContentScanner   : Crawler, emails, phones, metadata
"""

import socket
import ssl
import json
import re
import time
import struct
import threading
import concurrent.futures
from datetime   import datetime, timezone
from typing     import Optional, List, Dict, Any, Tuple
from urllib.parse import urlparse, urljoin

from PyQt6.QtCore import QThread, pyqtSignal, QObject


# ── Common result type ────────────────────────────────────────────────────────

class Finding:
    """A single discovered piece of information."""
    def __init__(self, category: str, key: str, value: str,
                 severity: str = "info", raw: Any = None):
        self.category  = category   # DNS, PORT, SSL, WEB...
        self.key       = key        # e.g. "A Record", "Open Port"
        self.value     = value      # Human-readable value
        self.severity  = severity   # info / low / medium / high / critical
        self.raw       = raw        # Raw data for export
        self.timestamp = datetime.now().strftime("%H:%M:%S")

    def to_dict(self) -> dict:
        return {
            "category":  self.category,
            "key":       self.key,
            "value":     self.value,
            "severity":  self.severity,
            "timestamp": self.timestamp,
        }


# ── Base scanner thread ───────────────────────────────────────────────────────

class BaseScanner(QThread):
    """Base class for all scanner threads."""
    finding    = pyqtSignal(object)   # Finding object
    progress   = pyqtSignal(int, str) # percent, message
    finished_ok = pyqtSignal(str)     # module name
    error      = pyqtSignal(str, str) # module name, error message

    def __init__(self, target: str, options: dict = None):
        super().__init__()
        self.target  = target.strip().lower().rstrip("/")
        self.options = options or {}
        self._stop   = False

    def stop(self):
        self._stop = True

    def emit_finding(self, category, key, value, severity="info", raw=None):
        f = Finding(category, key, value, severity, raw)
        self.finding.emit(f)

    def run(self):
        raise NotImplementedError


# ─────────────────────────────────────────────────────────────────────────────
# DNS Scanner
# ─────────────────────────────────────────────────────────────────────────────

class DNSScanner(BaseScanner):
    """
    Full DNS enumeration:
    - A, AAAA, MX, NS, TXT, CNAME, SOA, PTR records
    - Zone transfer attempt (AXFR)
    - Wildcard detection
    """

    # Common subdomains for brute-force
    COMMON_SUBS = [
        "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
        "portal", "vpn", "remote", "secure", "shop", "blog", "forum",
        "support", "help", "docs", "dashboard", "app", "mobile", "m",
        "smtp", "pop", "imap", "webmail", "ns1", "ns2", "mx", "mx1",
        "gateway", "proxy", "cdn", "static", "assets", "media", "img",
        "images", "upload", "uploads", "download", "downloads", "backup",
        "old", "new", "beta", "alpha", "demo", "stage", "prod", "uat",
        "jenkins", "gitlab", "github", "jira", "confluence", "wiki",
        "monitor", "status", "health", "metrics", "grafana", "kibana",
        "elasticsearch", "redis", "db", "database", "mysql", "mongo",
        "ssh", "rdp", "cpanel", "plesk", "whm", "webdisk", "autodiscover",
        "autoconfig", "calendar", "contacts", "exchange", "owa",
    ]

    def run(self):
        domain = self.target
        if domain.startswith("http"):
            domain = urlparse(domain).netloc or domain

        self.progress.emit(5, f"فحص DNS لـ {domain}")

        try:
            import dns.resolver
            import dns.zone
            import dns.query
            import dns.exception
        except ImportError:
            # Fallback to socket-based DNS
            self._socket_dns(domain)
            self.finished_ok.emit("DNS")
            return

        resolver = dns.resolver.Resolver()
        resolver.timeout  = 3
        resolver.lifetime = 6

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        total = len(record_types)

        for i, rtype in enumerate(record_types):
            if self._stop: break
            self.progress.emit(5 + i * 10, f"جلب سجلات {rtype}...")
            try:
                answers = resolver.resolve(domain, rtype)
                for rdata in answers:
                    val = str(rdata)
                    sev = "info"
                    if rtype == "TXT" and any(x in val.lower() for x in ["spf", "dmarc"]):
                        sev = "low"
                    self.emit_finding("DNS", f"سجل {rtype}", val, sev)
            except Exception:
                pass

        # Reverse DNS
        self.progress.emit(75, "Reverse DNS lookup...")
        try:
            answers = resolver.resolve(domain, "A")
            for rdata in answers:
                ip = str(rdata)
                try:
                    rev = socket.gethostbyaddr(ip)
                    self.emit_finding("DNS", "Reverse DNS", f"{ip} → {rev[0]}", "info")
                except Exception:
                    pass
        except Exception:
            pass

        # Zone transfer attempt
        self.progress.emit(80, "محاولة Zone Transfer (AXFR)...")
        try:
            ns_answers = resolver.resolve(domain, "NS")
            for ns in ns_answers:
                ns_str = str(ns).rstrip(".")
                try:
                    ns_ip = socket.gethostbyname(ns_str)
                    z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
                    self.emit_finding("DNS", "⚠️ Zone Transfer ناجح!",
                                      f"NS: {ns_str} — تسرّب {len(z.nodes)} سجل",
                                      "critical")
                    for name in z.nodes.keys():
                        self.emit_finding("DNS", "AXFR Record", str(name), "high")
                except Exception:
                    pass
        except Exception:
            pass

        # Wildcard check
        self.progress.emit(90, "فحص Wildcard...")
        try:
            fake = f"phantom-recon-{int(time.time())}.{domain}"
            socket.gethostbyname(fake)
            self.emit_finding("DNS", "⚠️ Wildcard DNS", "الدومين يقبل أي subdomain", "medium")
        except socket.gaierror:
            self.emit_finding("DNS", "Wildcard DNS", "غير مفعّل ✓", "info")

        self.progress.emit(100, "DNS مكتمل")
        self.finished_ok.emit("DNS")

    def _socket_dns(self, domain: str):
        """Fallback DNS using socket."""
        try:
            results = socket.getaddrinfo(domain, None)
            seen = set()
            for r in results:
                ip = r[4][0]
                if ip not in seen:
                    seen.add(ip)
                    self.emit_finding("DNS", "عنوان IP", ip, "info")
        except Exception as e:
            self.error.emit("DNS", str(e))


# ─────────────────────────────────────────────────────────────────────────────
# Port Scanner
# ─────────────────────────────────────────────────────────────────────────────

class PortScanner(BaseScanner):
    """
    TCP port scanner with:
    - Configurable port range
    - Concurrent scanning
    - Service detection
    - Banner grabbing
    """

    # Well-known service map
    SERVICES = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPCBind",
        135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
        443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP/TLS",
        631: "IPP", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
        1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 2375: "Docker",
        2376: "Docker TLS", 3000: "Dev Server", 3306: "MySQL",
        3389: "RDP", 4369: "RabbitMQ", 5000: "Flask/Dev",
        5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB",
        6379: "Redis", 6443: "Kubernetes", 7000: "Cassandra",
        8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
        8888: "Jupyter", 9000: "PHP-FPM", 9090: "Prometheus",
        9200: "Elasticsearch", 9300: "Elasticsearch-Node",
        11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB",
        50000: "SAP", 61616: "ActiveMQ",
    }

    # Severity by service (dangerous if open)
    DANGEROUS = {23, 135, 139, 445, 161, 1433, 2375, 3389, 5900,
                 6379, 9200, 11211, 27017, 4369, 5984}

    def run(self):
        target = self.target
        if target.startswith("http"):
            target = urlparse(target).netloc or target
        target = target.split(":")[0]  # Remove port if present

        # Resolve to IP
        try:
            ip = socket.gethostbyname(target)
            self.emit_finding("PORT", "IP الهدف", ip, "info")
        except Exception as e:
            self.error.emit("PORT", f"لا يمكن حل الدومين: {e}")
            return

        port_range = self.options.get("port_range", "common")
        timeout    = self.options.get("timeout", 1.0)
        threads    = self.options.get("threads", 200)

        if port_range == "common":
            ports = list(self.SERVICES.keys()) + [8008, 8081, 8888, 9443]
        elif port_range == "top1000":
            ports = self._top1000()
        elif port_range == "full":
            ports = list(range(1, 65536))
        else:
            ports = list(self.SERVICES.keys())

        ports = sorted(set(ports))
        total = len(ports)
        open_ports = []

        self.progress.emit(5, f"فحص {total} منفذ على {ip}...")

        done = [0]
        lock = threading.Lock()

        def scan_port(port: int) -> Optional[Tuple[int, str]]:
            if self._stop:
                return None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    banner = self._grab_banner(sock, port)
                    sock.close()
                    return (port, banner)
                sock.close()
            except Exception:
                pass
            finally:
                with lock:
                    done[0] += 1
                    if done[0] % 50 == 0:
                        pct = int(5 + (done[0] / total) * 85)
                        self.progress.emit(pct, f"فحص... {done[0]}/{total}")
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(scan_port, p): p for p in ports}
            for fut in concurrent.futures.as_completed(futures):
                if self._stop:
                    break
                res = fut.result()
                if res:
                    port, banner = res
                    open_ports.append(port)
                    service = self.SERVICES.get(port, "Unknown")
                    sev = "critical" if port in self.DANGEROUS else \
                          "high"     if port in {22, 25, 21} else "medium"

                    val = f"{port}/TCP  {service}"
                    if banner:
                        val += f"  |  {banner[:80]}"
                    self.emit_finding("PORT", f"منفذ مفتوح", val, sev)

        self.progress.emit(100, f"اكتمل — {len(open_ports)} منفذ مفتوح")
        self.emit_finding("PORT", "ملخص", f"{len(open_ports)} منفذ مفتوح من {total} فُحص", "info")
        self.finished_ok.emit("PORT")

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """Try to grab service banner."""
        try:
            if port in (80, 8080, 8000, 8008):
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner automatically
            elif port == 22:
                pass  # SSH sends banner automatically
            else:
                sock.send(b"\r\n")

            sock.settimeout(1)
            banner = sock.recv(256).decode("utf-8", errors="replace").strip()
            # Clean up
            banner = banner.replace("\r", " ").replace("\n", " ")[:100]
            return banner
        except Exception:
            return ""

    def _top1000(self) -> List[int]:
        """Return top 1000 most common ports."""
        common = list(self.SERVICES.keys())
        extra  = list(range(1, 1024))
        return sorted(set(common + extra))[:1000]


# ─────────────────────────────────────────────────────────────────────────────
# WHOIS Scanner
# ─────────────────────────────────────────────────────────────────────────────

class WHOISScanner(BaseScanner):
    """Domain WHOIS registration information."""

    def run(self):
        domain = self.target
        if domain.startswith("http"):
            domain = urlparse(domain).netloc or domain
        domain = domain.split(":")[0]

        self.progress.emit(20, "جلب بيانات WHOIS...")

        try:
            import whois
            w = whois.whois(domain)

            fields = [
                ("registrar",          "المسجّل (Registrar)"),
                ("creation_date",      "تاريخ التسجيل"),
                ("expiration_date",    "تاريخ الانتهاء"),
                ("updated_date",       "آخر تحديث"),
                ("name_servers",       "Name Servers"),
                ("org",                "المنظمة"),
                ("country",            "الدولة"),
                ("emails",             "الإيميلات"),
                ("registrant_name",    "اسم المسجّل"),
                ("admin_email",        "إيميل الإدارة"),
                ("status",             "الحالة"),
                ("dnssec",             "DNSSEC"),
            ]

            for field, label in fields:
                val = getattr(w, field, None) or w.get(field)
                if val:
                    if isinstance(val, list):
                        val = " | ".join(str(v) for v in val[:5])
                    else:
                        val = str(val)
                    if val.strip() and val != "None":
                        # Check expiry
                        sev = "info"
                        if field == "expiration_date":
                            try:
                                from datetime import datetime
                                exp_str = val.split("|")[0].strip()
                                exp = datetime.strptime(exp_str[:10], "%Y-%m-%d")
                                days = (exp - datetime.now()).days
                                if days < 30:
                                    sev = "high"
                                    val += f"  ⚠️ ينتهي خلال {days} يوم!"
                                elif days < 90:
                                    sev = "medium"
                            except Exception:
                                pass
                        self.emit_finding("WHOIS", label, val, sev)

            # Privacy check
            text = str(w).lower()
            if any(x in text for x in ["privacy", "redacted", "protected", "proxy"]):
                self.emit_finding("WHOIS", "حماية الخصوصية", "مفعّلة — البيانات محجوبة", "low")
            else:
                self.emit_finding("WHOIS", "حماية الخصوصية", "غير مفعّلة — البيانات مكشوفة ⚠️", "medium")

        except ImportError:
            self._fallback_whois(domain)
        except Exception as e:
            self._fallback_whois(domain)

        self.progress.emit(100, "WHOIS مكتمل")
        self.finished_ok.emit("WHOIS")

    def _fallback_whois(self, domain: str):
        """Socket-based WHOIS fallback."""
        try:
            tld = domain.split(".")[-1]
            server_map = {
                "com": "whois.verisign-grs.com",
                "net": "whois.verisign-grs.com",
                "org": "whois.pir.org",
                "io":  "whois.nic.io",
                "sa":  "whois.nic.sa",
                "ae":  "whois.aeda.net.ae",
            }
            server = server_map.get(tld, f"whois.nic.{tld}")

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((server, 43))
            s.send(f"{domain}\r\n".encode())

            response = b""
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                response += chunk
            s.close()

            text = response.decode("utf-8", errors="replace")
            for line in text.splitlines():
                if ":" in line and not line.startswith("%"):
                    key, _, val = line.partition(":")
                    key = key.strip()
                    val = val.strip()
                    if val and len(val) < 200:
                        self.emit_finding("WHOIS", key, val, "info")

        except Exception as e:
            self.error.emit("WHOIS", f"WHOIS فشل: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# SSL Scanner
# ─────────────────────────────────────────────────────────────────────────────

class SSLScanner(BaseScanner):
    """SSL/TLS certificate analysis."""

    WEAK_CIPHERS = [
        "RC4", "DES", "3DES", "MD5", "EXPORT", "NULL",
        "ANON", "ADH", "AECDH",
    ]

    def run(self):
        host = self.target
        if host.startswith("http"):
            host = urlparse(host).netloc or host
        host = host.split(":")[0]

        self.progress.emit(10, "الاتصال بـ SSL/TLS...")

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            with socket.create_connection((host, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert     = ssock.getpeercert()
                    der_cert = ssock.getpeercert(binary_form=True)
                    cipher   = ssock.cipher()
                    version  = ssock.version()

            self.progress.emit(40, "تحليل الشهادة...")

            # TLS Version
            sev = "info" if version in ("TLSv1.2", "TLSv1.3") else "high"
            self.emit_finding("SSL", "إصدار TLS", version or "Unknown", sev)

            # Cipher
            if cipher:
                cipher_name = cipher[0]
                cipher_bits = cipher[2]
                weak = any(w in cipher_name.upper() for w in self.WEAK_CIPHERS)
                sev = "critical" if weak else "info"
                self.emit_finding("SSL", "Cipher Suite", f"{cipher_name} ({cipher_bits} bits)", sev)

            # Parse cert
            if cert:
                # Subject
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer",  []))

                cn = subject.get("commonName", "")
                if cn:
                    self.emit_finding("SSL", "Common Name (CN)", cn, "info")

                org = subject.get("organizationName", "")
                if org:
                    self.emit_finding("SSL", "المنظمة", org, "info")

                issuer_cn = issuer.get("commonName", "")
                if issuer_cn:
                    self.emit_finding("SSL", "الجهة المُصدِرة", issuer_cn, "info")

                # Validity
                not_before = cert.get("notBefore", "")
                not_after  = cert.get("notAfter",  "")
                if not_after:
                    try:
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days = (exp - datetime.now()).days
                        sev = "critical" if days < 0 else \
                              "high"     if days < 14 else \
                              "medium"   if days < 30 else "info"
                        exp_str = f"{not_after}  ({days} يوم متبقي)"
                        if days < 0:
                            exp_str += "  ❌ منتهية الصلاحية!"
                        self.emit_finding("SSL", "انتهاء الصلاحية", exp_str, sev)
                    except Exception:
                        self.emit_finding("SSL", "انتهاء الصلاحية", not_after, "info")

                if not_before:
                    self.emit_finding("SSL", "تاريخ الإصدار", not_before, "info")

                # SANs (Subject Alternative Names)
                sans = cert.get("subjectAltName", [])
                if sans:
                    san_list = [v for t, v in sans if t == "DNS"]
                    self.emit_finding("SSL", f"SANs ({len(san_list)})",
                                      " | ".join(san_list[:20]), "info")
                    # Potential subdomains
                    for san in san_list:
                        if san.startswith("*."):
                            self.emit_finding("SSL", "Wildcard SAN", san, "low")

                # Serial number
                serial = cert.get("serialNumber", "")
                if serial:
                    self.emit_finding("SSL", "Serial Number", serial, "info")

            self.progress.emit(85, "فحص HTTP Headers...")

            # Check HSTS
            try:
                import urllib.request
                req = urllib.request.Request(
                    f"https://{host}",
                    headers={"User-Agent": "Mozilla/5.0 (PhantomRecon/1.0)"}
                )
                ctx2 = ssl.create_default_context()
                ctx2.check_hostname = False
                ctx2.verify_mode    = ssl.CERT_NONE
                with urllib.request.urlopen(req, context=ctx2, timeout=8) as resp:
                    headers = dict(resp.headers)
                    hsts = headers.get("Strict-Transport-Security", "")
                    if hsts:
                        self.emit_finding("SSL", "HSTS", hsts, "info")
                    else:
                        self.emit_finding("SSL", "HSTS", "غير مفعّل ⚠️", "medium")
            except Exception:
                pass

        except ssl.SSLError as e:
            self.emit_finding("SSL", "SSL Error", str(e), "high")
        except ConnectionRefusedError:
            self.emit_finding("SSL", "HTTPS", "المنفذ 443 مغلق", "medium")
        except Exception as e:
            self.error.emit("SSL", str(e))

        self.progress.emit(100, "SSL مكتمل")
        self.finished_ok.emit("SSL")


# ─────────────────────────────────────────────────────────────────────────────
# Web Scanner
# ─────────────────────────────────────────────────────────────────────────────

class WebScanner(BaseScanner):
    """
    Web technology detection, headers analysis,
    robots.txt, sitemap, forms, emails, links.
    """

    CMS_SIGNATURES = {
        "WordPress":   ["/wp-content/", "/wp-includes/", "wp-json"],
        "Joomla":      ["/components/com_", "Joomla!", "/media/jui/"],
        "Drupal":      ["Drupal.settings", "/sites/default/", "drupal.js"],
        "Magento":     ["Mage.Cookies", "/skin/frontend/", "MAGE_"],
        "Shopify":     ["cdn.shopify.com", "Shopify.theme", "shopify_pay"],
        "Wix":         ["wix.com", "_wix_", "X-Wix-"],
        "PrestaShop":  ["prestashop", "presta_shop"],
        "OpenCart":    ["catalog/view/theme", "OpenCart"],
        "Laravel":     ["laravel_session", "XSRF-TOKEN"],
        "Django":      ["csrfmiddlewaretoken", "Django"],
        "Flask":       ["Werkzeug", "flask"],
        "React":       ["__REACT_DEVTOOLS", "_reactFiber"],
        "Angular":     ["ng-version", "angular.min.js"],
        "Vue":         ["__vue__", "vue.min.js", "vue.runtime"],
        "Next.js":     ["__NEXT_DATA__", "_next/static"],
        "Nuxt.js":     ["__NUXT__", "_nuxt/"],
    }

    SERVER_SIGNATURES = {
        "Apache":   ["Apache", "apache"],
        "Nginx":    ["nginx", "Nginx"],
        "IIS":      ["Microsoft-IIS", "IIS"],
        "LiteSpeed": ["LiteSpeed"],
        "Caddy":    ["Caddy"],
        "Tomcat":   ["Apache-Coyote", "Tomcat"],
        "Node.js":  ["Node.js", "Express"],
    }

    SECURITY_HEADERS = [
        ("X-Frame-Options",           "Clickjacking Protection"),
        ("X-XSS-Protection",          "XSS Protection"),
        ("X-Content-Type-Options",     "MIME Sniffing Protection"),
        ("Content-Security-Policy",    "CSP"),
        ("Referrer-Policy",            "Referrer Policy"),
        ("Permissions-Policy",         "Permissions Policy"),
        ("Strict-Transport-Security",  "HSTS"),
        ("X-Permitted-Cross-Domain-Policies", "Cross-Domain Policy"),
    ]

    def run(self):
        base_url = self.target
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"

        self.progress.emit(5, "الاتصال بالموقع...")

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }

        try:
            import requests
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

            session = requests.Session()
            session.headers.update(headers)
            session.max_redirects = 5

            resp = session.get(base_url, timeout=15, verify=False)
            final_url = resp.url
            self.emit_finding("WEB", "URL النهائي", final_url, "info")
            self.emit_finding("WEB", "HTTP Status",
                              f"{resp.status_code} {resp.reason}", "info")

            self.progress.emit(20, "تحليل HTTP Headers...")
            self._analyze_headers(resp.headers)

            self.progress.emit(40, "كشف التقنيات...")
            html = resp.text
            self._detect_technologies(html, resp.headers, base_url)

            self.progress.emit(55, "فحص Security Headers...")
            self._check_security_headers(resp.headers)

            self.progress.emit(65, "استخراج الروابط والإيميلات...")
            self._extract_content(html, base_url)

            self.progress.emit(75, "فحص robots.txt...")
            self._check_robots(session, base_url)

            self.progress.emit(82, "فحص sitemap.xml...")
            self._check_sitemap(session, base_url)

            self.progress.emit(88, "فحص ملفات حساسة...")
            self._check_sensitive_files(session, base_url)

            self.progress.emit(95, "فحص Cookies...")
            self._analyze_cookies(resp.cookies)

        except ImportError:
            self._fallback_web(base_url)
        except Exception as e:
            self.error.emit("WEB", str(e))

        self.progress.emit(100, "Web مكتمل")
        self.finished_ok.emit("WEB")

    def _analyze_headers(self, headers):
        important = [
            "Server", "X-Powered-By", "X-Generator", "X-Backend-Server",
            "Via", "X-Forwarded-For", "CF-RAY", "X-Cache",
            "Access-Control-Allow-Origin",
        ]
        for h in important:
            val = headers.get(h, "")
            if val:
                sev = "medium" if h in ("X-Powered-By", "Server", "X-Generator") else "info"
                self.emit_finding("WEB", f"Header: {h}", val, sev)

        # WAF detection
        waf_headers = {
            "CF-RAY":        "Cloudflare",
            "X-Sucuri-ID":   "Sucuri WAF",
            "X-Akamai-Transformed": "Akamai",
            "X-CDN":         "CDN",
            "X-Varnish":     "Varnish Cache",
        }
        for h, waf in waf_headers.items():
            if headers.get(h):
                self.emit_finding("WEB", "WAF/CDN", waf, "info")

    def _detect_technologies(self, html: str, headers, base_url: str):
        # CMS
        for cms, signatures in self.CMS_SIGNATURES.items():
            if any(sig in html for sig in signatures):
                self.emit_finding("WEB", "CMS", cms, "medium")

        # Server
        server = headers.get("Server", "")
        for srv, sigs in self.SERVER_SIGNATURES.items():
            if any(s in server for s in sigs) or any(s in html for s in sigs):
                self.emit_finding("WEB", "Web Server", srv, "info")

        # Powered by
        powered = headers.get("X-Powered-By", "")
        if powered:
            self.emit_finding("WEB", "Powered By", powered, "medium")

        # PHP version exposure
        php_match = re.search(r"PHP/([\d.]+)", str(headers) + html)
        if php_match:
            self.emit_finding("WEB", "إصدار PHP مكشوف ⚠️", php_match.group(1), "high")

        # WordPress version
        wp_match = re.search(r'content="WordPress ([\d.]+)"', html)
        if wp_match:
            self.emit_finding("WEB", "إصدار WordPress", wp_match.group(1), "medium")

        # JavaScript libraries
        js_libs = {
            "jQuery":    r'jquery[/-]([\d.]+)',
            "Bootstrap": r'bootstrap[/-]([\d.]+)',
            "React":     r'"react"[:\s]+"([\d.]+)"',
            "Vue":       r'Vue\.version\s*=\s*"([\d.]+)"',
            "Angular":   r'"@angular/core":\s*"([\d.]+)"',
        }
        for lib, pattern in js_libs.items():
            m = re.search(pattern, html, re.IGNORECASE)
            if m:
                self.emit_finding("WEB", f"مكتبة JS: {lib}", m.group(1), "info")
            elif lib.lower() in html.lower():
                self.emit_finding("WEB", f"مكتبة JS: {lib}", "مكتشفة", "info")

    def _check_security_headers(self, headers):
        for header, name in self.SECURITY_HEADERS:
            val = headers.get(header, "")
            if val:
                self.emit_finding("WEB", f"✓ {name}", val[:100], "info")
            else:
                self.emit_finding("WEB", f"✗ {name} مفقود", "غير مضبوط", "medium")

    def _extract_content(self, html: str, base_url: str):
        # Emails
        emails = set(re.findall(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", html
        ))
        for email in list(emails)[:20]:
            self.emit_finding("WEB", "إيميل مكتشف", email, "low")

        # Phone numbers
        phones = set(re.findall(
            r"(?:\+?966|00966|0)?[- ]?(?:5[0-9]|[234])[0-9]{7}|"
            r"\+?[\d\s\-\(\)]{10,18}", html
        ))
        for phone in list(phones)[:10]:
            phone = phone.strip()
            if len(phone) >= 10:
                self.emit_finding("WEB", "رقم هاتف", phone, "low")

        # Count links
        links = re.findall(r'href=["\']([^"\']+)["\']', html)
        external = [l for l in links if l.startswith("http") and
                    urlparse(base_url).netloc not in l]
        self.emit_finding("WEB", "روابط خارجية",
                          f"{len(external)} رابط خارجي", "info")

        # Forms
        forms = re.findall(r'<form[^>]*>', html, re.IGNORECASE)
        if forms:
            self.emit_finding("WEB", "نماذج HTML", f"{len(forms)} نموذج", "low")
            # Login forms
            if any("password" in f.lower() or "login" in f.lower() for f in forms):
                self.emit_finding("WEB", "نموذج تسجيل دخول", "موجود ⚠️", "medium")

        # API endpoints
        apis = re.findall(r'["\'](/api/[^"\'?\s]+)', html)
        for api in set(apis)[:10]:
            self.emit_finding("WEB", "API Endpoint", api, "medium")

        # Comments
        comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        for c in comments[:5]:
            c = c.strip()[:100]
            if c and len(c) > 10:
                self.emit_finding("WEB", "HTML Comment", c, "low")

    def _check_robots(self, session, base_url: str):
        try:
            r = session.get(f"{base_url}/robots.txt", timeout=8, verify=False)
            if r.status_code == 200:
                disallowed = re.findall(r"Disallow:\s*(.+)", r.text)
                self.emit_finding("WEB", "robots.txt", f"{len(disallowed)} مسار محظور", "info")
                for path in disallowed[:15]:
                    self.emit_finding("WEB", "Disallow", path.strip(), "low")
        except Exception:
            pass

    def _check_sitemap(self, session, base_url: str):
        for path in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap.php"]:
            try:
                r = session.get(f"{base_url}{path}", timeout=8, verify=False)
                if r.status_code == 200 and "xml" in r.text.lower():
                    urls = re.findall(r"<loc>(.*?)</loc>", r.text)
                    self.emit_finding("WEB", "Sitemap", f"{len(urls)} URL في {path}", "info")
                    break
            except Exception:
                pass

    def _check_sensitive_files(self, session, base_url: str):
        sensitive = [
            ("/.git/HEAD",         "Git Repository مكشوف ⚠️",   "critical"),
            ("/.env",              "ملف .env مكشوف ⚠️",         "critical"),
            ("/config.php",        "Config PHP مكشوف",           "high"),
            ("/wp-config.php.bak", "WordPress Config Backup",    "critical"),
            ("/phpinfo.php",       "PHP Info مكشوف",              "high"),
            ("/admin",             "لوحة إدارة",                 "medium"),
            ("/administrator",     "Joomla Admin",               "medium"),
            ("/wp-admin",          "WordPress Admin",            "medium"),
            ("/login",             "صفحة تسجيل دخول",           "low"),
            ("/.htaccess",         "htaccess مكشوف",             "medium"),
            ("/backup.zip",        "ملف Backup",                 "critical"),
            ("/db.sql",            "ملف قاعدة بيانات",           "critical"),
            ("/server-status",     "Apache Status مكشوف",        "high"),
            ("/api/v1",            "API v1 Endpoint",            "medium"),
            ("/api/v2",            "API v2 Endpoint",            "medium"),
            ("/.DS_Store",         "DS_Store مكشوف",             "medium"),
        ]

        for path, label, sev in sensitive:
            if self._stop:
                break
            try:
                r = session.get(f"{base_url}{path}", timeout=5, verify=False,
                                allow_redirects=False)
                if r.status_code in (200, 403, 401):
                    status = {200: "✓ مكشوف", 403: "محظور (403)", 401: "يحتاج تسجيل (401)"}
                    self.emit_finding("WEB", label,
                                      f"{status.get(r.status_code)} — {path}", sev)
            except Exception:
                pass

    def _analyze_cookies(self, cookies):
        for cookie in cookies:
            flags = []
            if not getattr(cookie, "secure", False):
                flags.append("بدون Secure ⚠️")
            if not getattr(cookie, "has_nonstandard_attr", lambda x: False)("HttpOnly"):
                flags.append("بدون HttpOnly ⚠️")
            sev = "medium" if flags else "info"
            val = f"{cookie.name}"
            if flags:
                val += f"  |  {', '.join(flags)}"
            self.emit_finding("WEB", "Cookie", val, sev)

    def _fallback_web(self, url: str):
        """Fallback using only stdlib."""
        try:
            import urllib.request, urllib.error
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 PhantomRecon/1.0"
            })
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                self.emit_finding("WEB", "HTTP Status", str(resp.status), "info")
                for h, v in resp.headers.items():
                    self.emit_finding("WEB", f"Header: {h}", v, "info")
                html = resp.read(100000).decode("utf-8", errors="replace")
                self._extract_content(html, url)
        except Exception as e:
            self.error.emit("WEB", str(e))


# ─────────────────────────────────────────────────────────────────────────────
# GeoIP Scanner
# ─────────────────────────────────────────────────────────────────────────────

class GeoScanner(BaseScanner):
    """IP Geolocation, ASN, and hosting info using free APIs."""

    def run(self):
        target = self.target
        if target.startswith("http"):
            target = urlparse(target).netloc or target
        target = target.split(":")[0]

        self.progress.emit(10, "حل عنوان IP...")

        try:
            ip = socket.gethostbyname(target)
        except Exception:
            ip = target

        self.emit_finding("GEO", "عنوان IP", ip, "info")
        self.progress.emit(30, "جلب بيانات الموقع...")

        # Try multiple free APIs
        apis = [
            f"https://ipapi.co/{ip}/json/",
            f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,city,lat,lon,isp,org,as,query",
            f"https://ipwhois.app/json/{ip}",
        ]

        data = None
        for api_url in apis:
            try:
                import urllib.request
                req = urllib.request.Request(api_url, headers={
                    "User-Agent": "Mozilla/5.0 PhantomRecon/1.0"
                })
                with urllib.request.urlopen(req, timeout=8) as resp:
                    data = json.loads(resp.read().decode())
                if data:
                    break
            except Exception:
                continue

        if data:
            geo_fields = [
                ("country",      "country",     "الدولة"),
                ("countryCode",  "country_code","كود الدولة"),
                ("region",       "region",      "المنطقة"),
                ("city",         "city",        "المدينة"),
                ("lat",          "latitude",    "خط العرض"),
                ("lon",          "longitude",   "خط الطول"),
                ("isp",          "org",         "مزود الخدمة (ISP)"),
                ("org",          "asn",         "منظمة ASN"),
                ("as",           "asn",         "رقم AS"),
            ]
            for k1, k2, label in geo_fields:
                val = data.get(k1) or data.get(k2)
                if val:
                    self.emit_finding("GEO", label, str(val), "info")

            # Maps link
            lat = data.get("lat") or data.get("latitude")
            lon = data.get("lon") or data.get("longitude")
            if lat and lon:
                maps_link = f"https://maps.google.com/?q={lat},{lon}"
                self.emit_finding("GEO", "خرائط Google", maps_link, "info")

        # Check if shared hosting
        self.progress.emit(70, "فحص Shared Hosting...")
        try:
            import urllib.request
            req = urllib.request.Request(
                f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                headers={"User-Agent": "PhantomRecon/1.0"}
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                reverse_data = resp.read().decode()
                domains = [d.strip() for d in reverse_data.splitlines() if d.strip()]
                if len(domains) > 1:
                    self.emit_finding("GEO", "Shared Hosting",
                                      f"{len(domains)} دومين على نفس IP ⚠️", "medium")
                    for d in domains[:10]:
                        self.emit_finding("GEO", "دومين مشترك", d, "info")
        except Exception:
            pass

        self.progress.emit(100, "GeoIP مكتمل")
        self.finished_ok.emit("GEO")


# ─────────────────────────────────────────────────────────────────────────────
# Subdomain Scanner
# ─────────────────────────────────────────────────────────────────────────────

class SubdomainScanner(BaseScanner):
    """Subdomain enumeration via brute-force + passive sources."""

    # Extended wordlist
    WORDLIST = [
        "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
        "portal", "vpn", "remote", "secure", "shop", "blog", "forum",
        "support", "help", "docs", "dashboard", "app", "mobile", "m",
        "smtp", "pop", "imap", "webmail", "ns1", "ns2", "mx", "mx1", "mx2",
        "gateway", "proxy", "cdn", "static", "assets", "media", "img",
        "images", "upload", "uploads", "download", "downloads", "backup",
        "old", "new", "beta", "alpha", "demo", "stage", "prod", "uat",
        "jenkins", "gitlab", "git", "jira", "confluence", "wiki",
        "monitor", "status", "health", "metrics", "grafana", "kibana",
        "elasticsearch", "redis", "db", "database", "mysql", "mongo",
        "ssh", "rdp", "cpanel", "plesk", "whm", "webdisk",
        "autodiscover", "autoconfig", "calendar", "contacts",
        "exchange", "owa", "crm", "erp", "hr", "payroll",
        "internal", "intranet", "extranet", "corp", "office",
        "cloud", "server", "host", "web", "web1", "web2",
        "api1", "api2", "v1", "v2", "sandbox", "preprod",
        "qa", "testing", "review", "preview", "uat2",
        "login", "auth", "sso", "oauth", "id", "accounts",
        "payment", "pay", "checkout", "billing", "invoice",
        "store", "catalog", "search", "assets2", "img2",
        "video", "audio", "stream", "live", "rtmp",
        "smtp2", "mail2", "mail3", "relay", "mta",
        "ldap", "ad", "dc", "dc1", "dc2", "pdc",
        "fw", "firewall", "router", "switch", "vpn2",
        "backup2", "dr", "failover", "standby",
        "analytics", "tracking", "tag", "pixel",
        "push", "notify", "notification", "socket",
        "chat", "messaging", "ws", "websocket",
        "mobile-api", "app-api", "ios", "android",
    ]

    def run(self):
        domain = self.target
        if domain.startswith("http"):
            domain = urlparse(domain).netloc or domain
        domain = domain.split(":")[0]

        self.progress.emit(5, f"بحث عن subdomains لـ {domain}...")
        found = set()

        # 1. Certificate Transparency (crt.sh)
        self.progress.emit(10, "جلب من Certificate Transparency...")
        ct_subs = self._from_crtsh(domain)
        for sub in ct_subs:
            if sub not in found:
                found.add(sub)
                self._verify_subdomain(sub, domain, "CT Log")

        # 2. HackerTarget passive
        self.progress.emit(30, "جلب من HackerTarget...")
        ht_subs = self._from_hackertarget(domain)
        for sub in ht_subs:
            if sub not in found:
                found.add(sub)
                self._verify_subdomain(sub, domain, "HackerTarget")

        # 3. Brute force
        self.progress.emit(45, "Brute force subdomains...")
        total = len(self.WORDLIST)
        done  = [0]
        lock  = threading.Lock()

        def check(word):
            if self._stop:
                return
            sub = f"{word}.{domain}"
            if sub in found:
                return
            try:
                ip = socket.gethostbyname(sub)
                with lock:
                    if sub not in found:
                        found.add(sub)
                        self.emit_finding(
                            "SUB", "Subdomain مكتشف",
                            f"{sub}  →  {ip}", "medium"
                        )
            except socket.gaierror:
                pass
            finally:
                with lock:
                    done[0] += 1
                    if done[0] % 20 == 0:
                        pct = 45 + int((done[0] / total) * 50)
                        self.progress.emit(pct, f"Brute force... {done[0]}/{total}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
            list(ex.map(check, self.WORDLIST))

        self.emit_finding("SUB", "ملخص",
                          f"{len(found)} subdomain مكتشف", "info")
        self.progress.emit(100, f"Subdomains مكتمل — {len(found)} نتيجة")
        self.finished_ok.emit("SUB")

    def _verify_subdomain(self, sub: str, domain: str, source: str):
        try:
            if not sub.endswith(f".{domain}"):
                sub = f"{sub}.{domain}" if "." not in sub else sub
            ip = socket.gethostbyname(sub)
            self.emit_finding("SUB", f"Subdomain ({source})",
                              f"{sub}  →  {ip}", "medium")
        except Exception:
            pass

    def _from_crtsh(self, domain: str) -> List[str]:
        try:
            import urllib.request
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            req = urllib.request.Request(url, headers={"User-Agent": "PhantomRecon/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                subs = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for s in name.splitlines():
                        s = s.strip().lstrip("*.")
                        if domain in s:
                            subs.add(s)
                return list(subs)
        except Exception:
            return []

    def _from_hackertarget(self, domain: str) -> List[str]:
        try:
            import urllib.request
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            req = urllib.request.Request(url, headers={"User-Agent": "PhantomRecon/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                text = resp.read().decode()
                subs = []
                for line in text.splitlines():
                    if "," in line:
                        sub = line.split(",")[0].strip()
                        if domain in sub:
                            subs.append(sub)
                return subs
        except Exception:
            return []


# ─────────────────────────────────────────────────────────────────────────────
# Google Dorks Generator
# ─────────────────────────────────────────────────────────────────────────────

class DorksGenerator:
    """Generate Google Dorks for a target domain."""

    @staticmethod
    def generate(domain: str) -> List[Tuple[str, str]]:
        d = domain
        return [
            (f'site:{d}',                             "الصفحات المفهرسة"),
            (f'site:{d} filetype:pdf',                "ملفات PDF"),
            (f'site:{d} filetype:doc OR docx',        "ملفات Word"),
            (f'site:{d} filetype:xls OR xlsx',        "ملفات Excel"),
            (f'site:{d} filetype:sql',                "ملفات SQL"),
            (f'site:{d} filetype:log',                "ملفات Log"),
            (f'site:{d} filetype:env',                "ملفات .env"),
            (f'site:{d} inurl:admin',                 "صفحات Admin"),
            (f'site:{d} inurl:login',                 "صفحات Login"),
            (f'site:{d} inurl:config',                "صفحات Config"),
            (f'site:{d} inurl:backup',                "ملفات Backup"),
            (f'site:{d} inurl:api',                   "API Endpoints"),
            (f'site:{d} intext:password',             "كلمات مرور مكشوفة"),
            (f'site:{d} intext:"error" OR "exception"', "رسائل الخطأ"),
            (f'site:{d} intext:"Index of"',           "Directory Listing"),
            (f'site:{d} inurl:wp-content',            "WordPress Content"),
            (f'site:{d} inurl:phpmyadmin',            "phpMyAdmin"),
            (f'"{d}" site:pastebin.com',              "Pastebin Leaks"),
            (f'"{d}" site:github.com',                "GitHub References"),
            (f'site:{d} ext:bak OR ext:old OR ext:orig', "Backup Files"),
        ]
