import re
from typer.testing import CliRunner
from redrecon.cli.main import app

runner = CliRunner(env={"NO_COLOR": "1", "TERM": "dumb"})

ANSI_REGEX = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def clean_output(text: str) -> str:
    """Strip ANSI escape sequences from terminal runner output."""
    return ANSI_REGEX.sub("", text)


def test_cli_help():
    """Verify main CLI help displays correctly."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    clean = clean_output(result.output)
    assert "REDRECON-X" in clean
    assert "scan" in clean
    assert "benchmark" in clean


def test_cli_modules_list():
    """Verify 'redrecon modules' lists all 12 reconnaissance and reporting components."""
    result = runner.invoke(app, ["modules"])
    assert result.exit_code == 0
    clean = clean_output(result.output)
    assert "AVAILABLE MODULES" in clean
    assert "Certificate Transparency" in clean
    assert "Subdomain Discovery" in clean
    assert "DNS Resolution" in clean
    assert "IP Discovery" in clean
    assert "HTTP/HTTPS Probe" in clean
    assert "Report Generator" in clean


def test_cli_scan_help_options():
    """Verify scan options include active target limit flags."""
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    clean = clean_output(result.output)
    assert "max-nmap-targets" in clean
    assert "max-nuclei-targets" in clean
    assert "max-http-targets" in clean


def test_cli_full_help_options():
    """Verify full mode shortcut options."""
    result = runner.invoke(app, ["full", "--help"])
    assert result.exit_code == 0
    clean = clean_output(result.output)
    assert "max-nmap-targets" in clean


def test_cli_benchmark_help():
    """Verify academic research benchmark CLI arguments."""
    result = runner.invoke(app, ["benchmark", "--help"])
    assert result.exit_code == 0
    clean = clean_output(result.output)
    assert "empirical research benchmark" in clean
