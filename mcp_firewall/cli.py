"""CLI entry point for mcp-firewall."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel

from . import __version__
from .config import generate_default_config, load_config


@click.group()
@click.version_option(__version__, prog_name="mcp-firewall")
def main() -> None:
    """mcp-firewall — Security gateway for AI agents 🛡️"""
    pass


@main.command()
@click.argument("server_args", nargs=-1, required=True)
@click.option("--config", "config_path", type=click.Path(exists=True), help="Path to mcp-firewall.yaml")
@click.option("--dashboard", is_flag=True, help="Enable real-time dashboard (Phase 3)")
@click.option("--dashboard-host", default="127.0.0.1", show_default=True, help="Dashboard bind host")
@click.option("--dashboard-port", default=9090, show_default=True, type=int, help="Dashboard bind port")
def wrap(server_args: tuple[str, ...], config_path: str | None, dashboard: bool,
         dashboard_host: str, dashboard_port: int) -> None:
    """Wrap an MCP server with mcp-firewall protection.

    Usage: mcp-firewall wrap -- npx @modelcontextprotocol/server-filesystem /tmp
    """
    console = Console(stderr=True)

    # Banner
    console.print(Panel(
        "[bold blue]mcp-firewall[/bold blue] v{} 🛡️\n[dim]Security gateway for AI agents[/dim]".format(__version__),
        border_style="blue",
        expand=False,
    ))

    # Load config
    config = load_config(config_path)
    console.print(f"  [dim]Config:[/dim] {config_path or 'defaults'}")
    console.print(f"  [dim]Default action:[/dim] {config.default_action.value}")
    console.print(f"  [dim]Rules:[/dim] {len(config.rules)}")
    console.print(f"  [dim]Agents:[/dim] {len(config.agents)}")
    console.print(f"  [dim]Audit:[/dim] {config.audit.path if config.audit.enabled else 'disabled'}")
    console.print()

    if dashboard:
        from .dashboard.server import start_dashboard
        start_dashboard(host=dashboard_host, port=dashboard_port)
        console.print(f"  [green]Dashboard:[/green] http://{dashboard_host}:{dashboard_port}")
        console.print()

    # Start proxy
    from .proxy.stdio import StdioProxy
    proxy = StdioProxy(config, console)

    try:
        exit_code = asyncio.run(proxy.run(list(server_args)))
        sys.exit(exit_code)
    except KeyboardInterrupt:
        console.print("\n  [dim]Shutting down...[/dim]")


@main.command()
@click.option("--enterprise", is_flag=True, help="Generate enterprise policy template")
@click.option("--output", type=click.Path(), default="mcp-firewall.yaml")
def init(enterprise: bool, output: str) -> None:
    """Generate a starter mcp-firewall.yaml configuration."""
    console = Console()

    if Path(output).exists():
        if not click.confirm(f"{output} already exists. Overwrite?"):
            return

    content = generate_enterprise_config() if enterprise else generate_default_config()
    Path(output).write_text(content)
    console.print(f"[green]✓[/green] Generated {output}")
    console.print(f"[dim]  Edit the file, then: mcp-firewall wrap -- <your-mcp-server>[/dim]")


def generate_enterprise_config() -> str:
    """Stricter variant of the default config: deny-by-default, tighter scanning."""
    return (
        generate_default_config()
        .replace("defaultAction: prompt", "defaultAction: deny", 1)
        .replace("sensitivity: medium", "sensitivity: high", 1)
        .replace("detectPII: false", "detectPII: true", 1)
        .replace("maxCalls: 200", "maxCalls: 60", 1)
    )


@main.command()
@click.option("--config", "config_path", type=click.Path(exists=True), default="mcp-firewall.yaml")
def validate(config_path: str) -> None:
    """Validate an mcp-firewall.yaml configuration."""
    console = Console()
    try:
        config = load_config(config_path)
        console.print(f"[green]✓[/green] Configuration valid")
        console.print(f"  [dim]Version:[/dim] {config.version}")
        console.print(f"  [dim]Default action:[/dim] {config.default_action.value}")
        console.print(f"  [dim]Rules:[/dim] {len(config.rules)}")
        console.print(f"  [dim]Agents:[/dim] {len(config.agents)}")
    except Exception as e:
        console.print(f"[red]✗[/red] Configuration error: {e}")
        sys.exit(1)


@main.command()
@click.option("--config", "config_path", type=click.Path(exists=True))
def audit(config_path: str | None) -> None:
    """Verify audit log integrity."""
    console = Console()
    config = load_config(config_path)

    from .audit.logger import AuditLogger
    logger = AuditLogger(config)

    if not logger.path.exists():
        console.print(f"[red]✗[/red] Audit log not found: {logger.path}")
        sys.exit(1)

    is_valid, count, error = logger.verify_chain()

    if is_valid:
        console.print(f"[green]✓[/green] Audit log integrity verified ({count} entries)")
    else:
        console.print(f"[red]✗[/red] Audit log integrity FAILED: {error}")
        sys.exit(1)


@main.command("scan")
@click.argument("server_args", nargs=-1, required=True)
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
@click.option("--severity", type=click.Choice(["critical", "high", "medium", "low"]), default="low")
def scan(server_args: tuple[str, ...], output_format: str, severity: str) -> None:
    """Pre-deployment security scan (powered by mcpwn).

    Usage: mcp-firewall scan -- python my_server.py
    """
    from .scanner import run_scan
    extra = []
    if output_format != "text":
        extra.extend(["--format", output_format])
    if severity != "low":
        extra.extend(["--severity", severity])
    exit_code = run_scan(list(server_args), extra)
    if exit_code < 0:
        Console().print("[yellow]Install mcpwn for scanning: pip install mcpwn[/yellow]")
        sys.exit(3)
    sys.exit(exit_code)


@main.group()
def report() -> None:
    """Generate compliance reports from audit logs."""
    pass


@report.command("dora")
@click.option("--audit-log", type=click.Path(exists=True), default="mcp-firewall.audit.jsonl")
@click.option("--output", type=click.Path(), help="Save report to file")
def report_dora(audit_log: str, output: str | None) -> None:
    """Generate DORA compliance report."""
    from .compliance.report import generate_dora_report
    _output_report(generate_dora_report(audit_log), output)


@report.command("finma")
@click.option("--audit-log", type=click.Path(exists=True), default="mcp-firewall.audit.jsonl")
@click.option("--output", type=click.Path(), help="Save report to file")
def report_finma(audit_log: str, output: str | None) -> None:
    """Generate FINMA compliance report."""
    from .compliance.report import generate_finma_report
    _output_report(generate_finma_report(audit_log), output)


@report.command("soc2")
@click.option("--audit-log", type=click.Path(exists=True), default="mcp-firewall.audit.jsonl")
@click.option("--output", type=click.Path(), help="Save report to file")
def report_soc2(audit_log: str, output: str | None) -> None:
    """Generate SOC 2 Type II evidence report."""
    from .compliance.report import generate_soc2_report
    _output_report(generate_soc2_report(audit_log), output)


def _output_report(content: str, output: str | None) -> None:
    console = Console()
    if output:
        Path(output).write_text(content)
        console.print(f"[green]✓[/green] Report saved to {output}")
    else:
        console.print(content)


@main.group()
def feed() -> None:
    """Manage threat feed rules."""
    pass


@feed.command("list")
@click.option("--rules-dir", type=click.Path(), help="Custom rules directory")
def feed_list(rules_dir: str | None) -> None:
    """List loaded threat feed rules."""
    from .threatfeed.loader import ThreatFeed

    console = Console()
    tf = ThreatFeed()

    # Load built-in rules
    builtin_dir = Path(__file__).parent / "threatfeed" / "rules"
    tf.load_directory(builtin_dir)

    if rules_dir:
        tf.load_directory(rules_dir)

    if not tf.rules:
        console.print("[yellow]No rules loaded[/yellow]")
        return

    from rich.table import Table
    table = Table(title="Threat Feed Rules")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Severity")
    table.add_column("Tags", style="dim")

    sev_colors = {"critical": "red", "high": "yellow", "medium": "bright_yellow", "low": "blue", "info": "white"}

    for r in tf.list_rules():
        color = sev_colors.get(r["severity"], "white")
        table.add_row(r["id"], r["name"], f"[{color}]{r['severity']}[/{color}]", r["tags"])

    console.print(table)


if __name__ == "__main__":
    main()
