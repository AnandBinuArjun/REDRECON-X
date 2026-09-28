from rich.panel import Panel
from rich.text import Text
from redrecon.core.logger import console

BANNER_ART = r"""
██████╗ ███████╗██████╗ ██████╗ ███████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║  ██║██████╔╝█████╗  ██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║  ██║██╔══██╗██╔══╝  ██║   ██║██║╚██╗██║
██║  ██║███████╗██████╔╝██████╔╝███████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
"""

TAGLINE = "WEB RECONNAISSANCE & ATTACK-SURFACE INTELLIGENCE FRAMEWORK"


def print_banner(version: str = "1.0.0"):
    banner_text = Text()
    banner_text.append(BANNER_ART, style="bold red")
    banner_text.append(f"\n      {TAGLINE}\n", style="bold white")
    banner_text.append(f"      [ Version {version} | Discover. Correlate. Understand. ]\n", style="dim cyan")
    banner_text.append("      [ Developer: AnandBinuArjun ]\n", style="bold red")

    panel = Panel(
        banner_text,
        border_style="red",
        subtitle="[dim red]Authorized Security Assessment Only[/dim red]",
        subtitle_align="right",
    )
    console.print(panel)
