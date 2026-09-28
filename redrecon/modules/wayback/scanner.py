import asyncio
import re
from typing import Any, Dict, List, Set
from urllib.parse import urlparse
import httpx
from redrecon.core.logger import get_logger
from redrecon.modules.base import BaseModule

logger = get_logger()

# Classification heuristics
CATEGORIES = {
    "API": re.compile(r"/(api|v\d+|graphql|rest|endpoints?)/", re.IGNORECASE),
    "Authentication": re.compile(r"/(login|signin|signup|auth|oauth|sso|register|password|session)", re.IGNORECASE),
    "Administrative": re.compile(r"/(admin|manage|dashboard|cpanel|portal|sysadmin|control|root)", re.IGNORECASE),
    "JavaScript": re.compile(r"\.(js|jsx|ts|tsx)(\?.*)?$", re.IGNORECASE),
    "Sensitive/Backup": re.compile(r"\.(bak|old|backup|sql|env|git|tar|gz|zip|conf|cfg|dump|swp)(\?.*)?$", re.IGNORECASE),
    "Documents": re.compile(r"\.(pdf|doc|docx|xls|xlsx|ppt|pptx|csv|txt|rtf)(\?.*)?$", re.IGNORECASE),
    "Static": re.compile(r"\.(png|jpg|jpeg|gif|svg|ico|css|woff|woff2|ttf|eot|webp)(\?.*)?$", re.IGNORECASE),
}


class WaybackScanner(BaseModule):
    """
    Wayback Machine Historical URL Discovery Module.
    Queries the Internet Archive CDX API for historical endpoints,
    normalizes URLs, deduplicates paths, and categorizes endpoints.
    """

    @property
    def name(self) -> str:
        return "Wayback Machine Discovery"

    @property
    def description(self) -> str:
        return "Discovers historical URLs and endpoints indexed in the Wayback Archive"

    def classify_url(self, url: str) -> str:
        """Classify a URL into functional categories."""
        parsed = urlparse(url)
        path_and_query = parsed.path + ("?" + parsed.query if parsed.query else "")

        for category, pattern in CATEGORIES.items():
            if pattern.search(path_and_query):
                return category
        return "Other"

    async def scan(self, domain: str, limit: int = 1000) -> Dict[str, Any]:
        logger.info(f"Querying Wayback CDX Archive for: [bold cyan]{domain}[/bold cyan]")
        url = (
            f"https://web.archive.org/cdx/search/cdx?"
            f"url=*.{domain}/*&output=json&collapse=urlkey&fl=original&limit={limit}"
        )

        all_urls: List[str] = []
        try:
            async with self.get_http_client(timeout=15.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    rows = resp.json()
                    # Skip header row if returned
                    if rows and rows[0] == ["original"]:
                        rows = rows[1:]
                    for r in rows:
                        if r and isinstance(r, list):
                            all_urls.append(r[0])
                        elif isinstance(r, str):
                            all_urls.append(r)
        except Exception as e:
            logger.debug(f"Wayback CDX API encountered issue: {e}")

        # Normalize and deduplicate
        unique_urls: Set[str] = set()
        classified: Dict[str, List[str]] = {cat: [] for cat in CATEGORIES}
        classified["Other"] = []

        for u in all_urls:
            u_clean = u.strip()
            if u_clean.startswith("http://") or u_clean.startswith("https://"):
                unique_urls.add(u_clean)

        for u in sorted(unique_urls):
            cat = self.classify_url(u)
            classified[cat].append(u)

        logger.info(
            f"Wayback discovery complete: [bold green]{len(unique_urls)}[/bold green] unique URLs "
            f"(from {len(all_urls)} archive records)"
        )

        return {
            "target": domain,
            "total_records": len(all_urls),
            "unique_count": len(unique_urls),
            "urls": sorted(list(unique_urls)),
            "classified": {cat: urls for cat, urls in classified.items() if urls},
            "summary_by_category": {cat: len(urls) for cat, urls in classified.items() if urls},
        }
