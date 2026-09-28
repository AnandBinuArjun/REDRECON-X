import asyncio
import os
import shutil
import socket
import tempfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional
from redrecon.core.logger import get_logger
from redrecon.models.asset import PortService
from redrecon.modules.base import BaseModule

logger = get_logger()

# Common port service name map for native fallback
COMMON_SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 81: "http-alt", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 587: "submission", 853: "dns-over-tls", 993: "imaps",
    995: "pop3s", 1080: "socks", 1433: "ms-sql-s", 1521: "oracle",
    2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl", 2086: "whm",
    2087: "whm-ssl", 2181: "zookeeper", 2375: "docker", 2376: "docker-ssl",
    3000: "ppp/react", 3128: "squid-http", 3306: "mysql", 3389: "ms-wbt-server",
    4000: "icq", 4200: "vrml-multi-user", 4443: "pharos", 5000: "upnp/flask",
    5432: "postgresql", 5601: "kibana", 5672: "amqp", 5900: "vnc",
    5984: "couchdb", 6379: "redis", 7000: "afs3-fileserver", 7001: "afs3-callback",
    8000: "http-alt", 8001: "vcom-tunnel", 8008: "http-alt", 8080: "http-proxy",
    8081: "blackice-icecap", 8082: "blackice-alerts", 8088: "radan-http",
    8090: "opslogic", 8181: "intermapper", 8443: "https-alt", 8500: "fmtp",
    8888: "http-alt", 9000: "cslistener", 9042: "cassandra", 9090: "zeus-admin",
    9092: "kafka", 9200: "wap-wsp", 9300: "vrstream", 9443: "tungsten-https",
    9999: "abyss", 10000: "snet-sensor-mgmt", 11211: "memcache",
    27017: "mongodb", 27018: "mongodb-alt", 50000: "iiimsf"
}


class NmapScanner(BaseModule):
    """
    Port Scanning & Service Fingerprinting Module.
    Uses Nmap with XML output parsing when available on system PATH;
    seamlessly falls back to an asynchronous native TCP port scanner.
    """

    @property
    def name(self) -> str:
        return "Port & Service Scanner"

    @property
    def description(self) -> str:
        return "Nmap XML integration with native async TCP socket fallback"

    def is_nmap_available(self) -> bool:
        return shutil.which("nmap") is not None

    async def scan_host_native(self, host_or_ip: str, ports: Optional[List[int]] = None) -> List[PortService]:
        """
        Pure-Python async socket port probe fallback.
        """
        target_ports = ports or self.config.custom_ports
        open_services: List[PortService] = []
        sem = asyncio.Semaphore(self.config.concurrency)

        async def _check_port(port: int):
            async with sem:
                try:
                    conn = asyncio.open_connection(host_or_ip, port)
                    _, writer = await asyncio.wait_for(conn, timeout=2.0)
                    writer.close()
                    await writer.wait_closed()

                    svc_name = COMMON_SERVICE_MAP.get(port, "unknown")
                    open_services.append(
                        PortService(
                            port=port,
                            protocol="tcp",
                            state="open",
                            service_name=svc_name,
                        )
                    )
                except Exception:
                    pass

        await asyncio.gather(*[_check_port(p) for p in target_ports], return_exceptions=True)
        return sorted(open_services, key=lambda s: s.port)

    async def scan_host_nmap(self, host_or_ip: str, top_ports: int = 100) -> List[PortService]:
        """
        Executes Nmap CLI and parses the XML output into PortService models.
        """
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name

        try:
            # -sT or -sS (use -sT for unprivileged safety)
            cmd = [
                "nmap",
                "-sT",
                "-T4",
                f"--top-ports={top_ports}",
                "-oX", xml_path,
                host_or_ip,
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

            if os.path.exists(xml_path):
                return self.parse_nmap_xml(xml_path)
            return []
        except Exception as e:
            logger.warning(f"Nmap execution failed: {e}. Falling back to native scanner.")
            return await self.scan_host_native(host_or_ip)
        finally:
            if os.path.exists(xml_path):
                try:
                    os.remove(xml_path)
                except Exception:
                    pass

    def parse_nmap_xml(self, xml_source: str) -> List[PortService]:
        """Parse Nmap XML output (from file path or raw XML string) to PortService objects."""
        ports_list: List[PortService] = []
        try:
            if os.path.exists(xml_source):
                tree = ET.parse(xml_source)  # nosec B314
                root = tree.getroot()
            else:
                root = ET.fromstring(xml_source)  # nosec B314

            for host in root.findall("host"):
                ports_elem = host.find("ports")
                if ports_elem is None:
                    continue
                for port_elem in ports_elem.findall("port"):
                    state_elem = port_elem.find("state")
                    if state_elem is not None and state_elem.get("state") == "open":
                        port_num = int(port_elem.get("portid", 0))
                        proto = port_elem.get("protocol", "tcp")
                        svc_elem = port_elem.find("service")

                        svc_name = svc_elem.get("name") if svc_elem is not None else None
                        product = svc_elem.get("product") if svc_elem is not None else None
                        version = svc_elem.get("version") if svc_elem is not None else None

                        ports_list.append(
                            PortService(
                                port=port_num,
                                protocol=proto,
                                state="open",
                                service_name=svc_name or COMMON_SERVICE_MAP.get(port_num, "unknown"),
                                product=product,
                                version=version,
                            )
                        )
        except Exception as e:
            logger.debug(f"Failed to parse Nmap XML: {e}")
        return sorted(ports_list, key=lambda s: s.port)

    async def scan(self, target: str) -> Dict[str, Any]:
        """Scan target using Nmap if available, otherwise native socket scanner."""
        engine_used = "nmap" if self.is_nmap_available() else "native_socket"
        logger.info(f"Port scanning [bold cyan]{target}[/bold cyan] using engine: [bold yellow]{engine_used}[/bold yellow]")

        if self.is_nmap_available():
            ports = await self.scan_host_nmap(target, top_ports=self.config.nmap_top_ports)
        else:
            ports = await self.scan_host_native(target)

        logger.info(f"Found [bold green]{len(ports)}[/bold green] open ports on {target}")
        return {
            "target": target,
            "engine": engine_used,
            "total_open_ports": len(ports),
            "ports": [p.model_dump() for p in ports],
        }

    async def scan_multiple(self, targets: List[str]) -> Dict[str, List[PortService]]:
        """Scan a list of targets (hostnames or IPs)."""
        logger.info(f"Port scanning [bold cyan]{len(targets)}[/bold cyan] assets...")
        results: Dict[str, List[PortService]] = {}

        # Limit concurrent host scans
        sem = asyncio.Semaphore(5)

        async def _scan(target: str):
            async with sem:
                res = await self.scan(target)
                port_models = [PortService(**p) for p in res.get("ports", [])]
                results[target] = port_models

        await asyncio.gather(*[_scan(t) for t in targets], return_exceptions=True)
        return results
