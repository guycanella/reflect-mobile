"""
Command-line interface for Reflect.
"""

import click
from rich.console import Console
from rich.table import Table

from reflect import __version__

# Rich console for beautiful output
console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="Reflect")
def main():
    """
    Reflect - Security testing tool for mobile apps.

    Uses Metamorphic Testing to detect authentication vulnerabilities
    in Android and iOS applications.
    """
    pass


@main.command()
@click.option(
    "--apk",
    type=click.Path(exists=True),
    help="Path to Android APK file",
)
@click.option(
    "--ipa",
    type=click.Path(exists=True),
    help="Path to iOS IPA file",
)
@click.option(
    "--mr",
    type=click.Choice(["MR1", "MR4", "MR2", "MR3", "MR5", "all"]),
    default="all",
    help="Which Metamorphic Relation to test (default: all)",
)
@click.option(
    "--report",
    type=click.Choice(["terminal", "html", "json"]),
    default="terminal",
    help="Report format (default: terminal)",
)
def test(apk, ipa, mr, report):
    """
    Run security tests on a mobile app.

    Examples:

        reflect test --apk ./app.apk

        reflect test --apk ./app.apk --mr MR4

        reflect test --ipa ./app.ipa --report html
    """
    # Validate that at least one app is provided
    if not apk and not ipa:
        console.print("[red]Error:[/red] You must provide --apk or --ipa")
        raise SystemExit(1)

    # Determine platform
    platform = "android" if apk else "ios"
    app_path = apk or ipa

    console.print(f"\n[bold blue]🔍 Reflect Security Test[/bold blue]\n")
    console.print(f"  App: [cyan]{app_path}[/cyan]")
    console.print(f"  Platform: [cyan]{platform}[/cyan]")
    console.print(f"  Tests: [cyan]{mr}[/cyan]")
    console.print(f"  Report: [cyan]{report}[/cyan]")
    console.print()

    # TODO: Implement actual testing logic
    # This will be connected to the orchestrator module
    console.print("[yellow]⚠️  Test execution not yet implemented[/yellow]")
    console.print("[dim]Next step: implement orchestrator.py[/dim]")


@main.command(name="list")
def list_mrs():
    """
    List all available Metamorphic Relations (tests).
    """
    table = Table(title="Available Metamorphic Relations")

    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("CWE", style="magenta")
    table.add_column("Vulnerability", style="white")
    table.add_column("Status", style="green")

    # MRs based on the paper
    mrs = [
        ("MR1", "CWE-295", "Improper Certificate Validation", "🟢 Ready"),
        ("MR4", "CWE-311", "Missing Encryption of Sensitive Data", "🟢 Ready"),
        ("MR2", "CWE-613", "Insufficient Session Expiration", "🟡 Planned"),
        ("MR3", "CWE-384", "Session Fixation", "🟡 Planned"),
        ("MR5", "CWE-288", "Authentication Bypass", "🟡 Planned"),
    ]

    for mr_id, cwe, vuln, status in mrs:
        table.add_row(mr_id, cwe, vuln, status)

    console.print()
    console.print(table)
    console.print()


@main.command()
def info():
    """
    Show information about the testing environment.
    """
    console.print("\n[bold blue]📋 Environment Information[/bold blue]\n")

    # TODO: Check actual installations
    checks = [
        ("Python", "✅", "Installed"),
        ("mitmproxy", "⚠️", "Not checked yet"),
        ("Maestro", "⚠️", "Not checked yet"),
        ("Android SDK", "⚠️", "Not checked yet"),
        ("iOS Simulator", "⚠️", "Not checked yet"),
    ]

    for tool, icon, status in checks:
        console.print(f"  {icon} {tool}: [dim]{status}[/dim]")

    console.print()


# Entry point when running with: python -m reflect
if __name__ == "__main__":
    main()