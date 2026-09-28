from redrecon.modules.base import BaseModule
from redrecon.modules.certificate.scanner import CertificateScanner
from redrecon.modules.subdomain.scanner import SubdomainScanner
from redrecon.modules.dns.scanner import DNSScanner
from redrecon.modules.ip.scanner import IPScanner
from redrecon.modules.http.scanner import HTTPScanner
from redrecon.modules.headers.analyzer import HeaderAnalyzer
from redrecon.modules.wayback.scanner import WaybackScanner
from redrecon.modules.nmap.scanner import NmapScanner
from redrecon.modules.nuclei.scanner import NucleiScanner
from redrecon.reporting.generator import ReportGenerator

MODULE_REGISTRY = {
    "01": ("Certificate Transparency", CertificateScanner),
    "02": ("Subdomain Discovery", SubdomainScanner),
    "03": ("DNS Resolution", DNSScanner),
    "04": ("IP Discovery", IPScanner),
    "05": ("HTTP/HTTPS Probe", HTTPScanner),
    "06": ("HTTP Title Detection", HTTPScanner),
    "07": ("HTTP Status Detection", HTTPScanner),
    "08": ("Security Header Analysis", HeaderAnalyzer),
    "09": ("Wayback URL Discovery", WaybackScanner),
    "10": ("Nmap Port Scanner", NmapScanner),
    "11": ("Nuclei Scanner", NucleiScanner),
    "12": ("Report Generator", ReportGenerator),
}

__all__ = [
    "BaseModule",
    "CertificateScanner",
    "SubdomainScanner",
    "DNSScanner",
    "IPScanner",
    "HTTPScanner",
    "HeaderAnalyzer",
    "WaybackScanner",
    "NmapScanner",
    "NucleiScanner",
    "MODULE_REGISTRY",
]
