from typer.testing import CliRunner
from redrecon.cli.main import app

runner = CliRunner()


def test_cli_help():
    """Verify main CLI help displays correctly."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "REDRECON-X" in result.output
    assert "scan" in result.output
    assert "benchmark" in result.output


def test_cli_modules_list():
    """Verify 'redrecon modules' lists all 12 reconnaissance and reporting components."""
    result = runner.invoke(app, ["modules"])
    assert result.exit_code == 0
    assert "AVAILABLE MODULES" in result.output
    assert "Certificate Transparency" in result.output
    assert "Subdomain Discovery" in result.output
    assert "DNS Resolution" in result.output
    assert "IP Discovery" in result.output
    assert "HTTP/HTTPS Probe" in result.output
    assert "Report Generator" in result.output


def test_cli_scan_help_options():
    """Verify scan options include active target limit flags."""
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--max-nmap-targets" in result.output
    assert "--max-nuclei-targets" in result.output
    assert "--max-http-targets" in result.output


def test_cli_full_help_options():
    """Verify full mode shortcut options."""
    result = runner.invoke(app, ["full", "--help"])
    assert result.exit_code == 0
    assert "--max-nmap-targets" in result.output


def test_cli_benchmark_help():
    """Verify academic research benchmark CLI arguments."""
    result = runner.invoke(app, ["benchmark", "--help"])
    assert result.exit_code == 0
    assert "empirical research benchmark" in result.output
