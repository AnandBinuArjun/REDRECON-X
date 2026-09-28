import logging
import sys
from typing import Optional
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Custom theme for REDRECON-X
REDRECON_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "critical": "bold white on red",
    "success": "bold green",
    "highlight": "bold magenta",
    "asset": "bold red",
    "port": "bright_blue",
    "domain": "bold bright_white",
})

console = Console(theme=REDRECON_THEME, legacy_windows=False)
error_console = Console(stderr=True, theme=REDRECON_THEME, legacy_windows=False)

_logger: Optional[logging.Logger] = None


def setup_logger(verbose: bool = False, log_file: Optional[str] = None) -> logging.Logger:
    global _logger
    if _logger is not None:
        return _logger

    level = logging.DEBUG if verbose else logging.INFO
    logger = logging.getLogger("redrecon")
    logger.setLevel(level)
    logger.handlers.clear()

    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        rich_tracebacks=True,
        tracebacks_show_locals=False,
    )
    rich_handler.setLevel(level)
    logger.addHandler(rich_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    _logger = logger
    return logger


def get_logger() -> logging.Logger:
    global _logger
    if _logger is None:
        _logger = setup_logger()
    return _logger
