import asyncio
import re
import time
from typing import Any, Dict, List, Optional
from bs4 import BeautifulSoup
import httpx
from redrecon.core.logger import get_logger
from redrecon.models.asset import HTTPService
from redrecon.modules.base import BaseModule

logger = get_logger()


class HTTPScanner(BaseModule):
    """
    Async HTTP/HTTPS Probing Module.
    Probes web services, extracts status codes, redirect chains, HTML titles,
    server banners, content types, and measures response latency.
    """

    @property
    def name(self) -> str:
        return "HTTP Reconnaissance"

    @property
    def description(self) -> str:
        return "Async HTTP/HTTPS probing with title, server, status, and redirect detection"

    def extract_title(self, html_text: str) -> Optional[str]:
        """Extract and sanitize HTML title tag."""
        if not html_text:
            return None
        try:
            soup = BeautifulSoup(html_text[:50000], "html.parser")
            if soup.title and soup.title.string:
                title = soup.title.string.strip()
                # Clean whitespace/newlines
                title = re.sub(r"\s+", " ", title)
                return title[:150]
        except Exception:
            pass

        # Regex fallback
        match = re.search(r"<title[^>]*>([^<]+)</title>", html_text[:50000], re.IGNORECASE)
        if match:
            return re.sub(r"\s+", " ", match.group(1).strip())[:150]
        return None

    async def probe_endpoint(self, url: str) -> Optional[Dict[str, Any]]:
        """Probe a specific HTTP or HTTPS endpoint."""
        start_time = time.perf_counter()
        try:
            async with self.get_http_client(timeout=self.config.timeout) as client:
                resp = await client.get(url)
                duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

                # Collect redirect history
                redirect_chain = [str(r.url) for r in resp.history]
                if redirect_chain:
                    redirect_chain.append(str(resp.url))

                title = self.extract_title(resp.text)
                server = resp.headers.get("server")
                content_type = resp.headers.get("content-type")

                return {
                    "url": str(resp.url),
                    "original_url": url,
                    "is_https": resp.url.scheme == "https",
                    "status_code": resp.status_code,
                    "title": title,
                    "server": server,
                    "content_type": content_type,
                    "response_time_ms": duration_ms,
                    "redirect_chain": redirect_chain,
                    "headers": dict(resp.headers),
                    "body_snippet": resp.text[:500] if resp.text else "",
                }
        except httpx.HTTPError:
            return None
        except Exception:
            return None

    async def probe_host(self, host: str) -> Optional[Dict[str, Any]]:
        """
        Probe host on HTTPS first, fallback to HTTP or report active service.
        """
        if self.config.probe_https:
            res_https = await self.probe_endpoint(f"https://{host}")
            if res_https:
                return res_https

        if self.config.probe_http:
            res_http = await self.probe_endpoint(f"http://{host}")
            if res_http:
                return res_http

        return None

    async def scan_hosts(self, hosts: List[str]) -> Dict[str, Dict[str, Any]]:
        """Probe multiple hosts concurrently."""
        logger.info(f"Probing HTTP/HTTPS services for [bold cyan]{len(hosts)}[/bold cyan] hosts...")
        sem = asyncio.Semaphore(self.config.concurrency)
        results: Dict[str, Dict[str, Any]] = {}

        async def _worker(host: str):
            async with sem:
                res = await self.probe_host(host)
                if res:
                    results[host] = res

        await asyncio.gather(*[_worker(h) for h in hosts], return_exceptions=True)

        logger.info(f"Discovered [bold green]{len(results)}[/bold green] active HTTP/HTTPS services")
        return results

    async def scan(self, target: str) -> Dict[str, Any]:
        """Single target scan helper."""
        res = await self.probe_host(target)
        return {
            "target": target,
            "has_service": res is not None,
            "service": res,
        }
