from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
import httpx
from redrecon.core.config import ScanConfig
from redrecon.core.logger import get_logger

logger = get_logger()


class BaseModule(ABC):
    """Abstract base class for all REDRECON-X scanner modules."""

    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self.logger = logger

    @property
    @abstractmethod
    def name(self) -> str:
        """Module display name."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Module functionality summary."""
        pass

    def get_http_client(self, timeout: Optional[float] = None) -> httpx.AsyncClient:
        """Create standard async HTTP client with project user-agent and settings."""
        return httpx.AsyncClient(
            timeout=timeout or self.config.timeout,
            headers={"User-Agent": self.config.user_agent},
            verify=self.config.verify_ssl,
            follow_redirects=self.config.follow_redirects,
            limits=httpx.Limits(
                max_connections=self.config.concurrency,
                max_keepalive_connections=self.config.concurrency // 2,
            ),
        )
