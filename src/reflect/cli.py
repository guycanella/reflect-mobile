"""
Command-line interface for Reflect.
"""

import click
from rich.console import Console
from rich.table import Table
from pathlib import Path

from reflect import __version__


# Rich console for beautiful output
console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="Reflect")
def cli():
    """
    Reflect - Security testing tool for mobile apps.

    Uses Metamorphic Testing to detect authentication vulnerabilities
    in Android and iOS applications.
    """
    pass


@cli.command()
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
@click.option(
    "--avd",
    default="reflect-test",
    help="Android Virtual Device name (default: reflect-test)",
)
@click.option(
    "--headless",
    is_flag=True,
    help="Run emulator without GUI (for CI/CD)",
)
def test(apk, ipa, mr, report, avd, headless):
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

    # iOS not yet implemented
    if ipa:
        console.print("[yellow]⚠️  iOS support not yet implemented[/yellow]")
        raise SystemExit(1)

    # Determine which MRs to run
    if mr == "all":
        mrs = ["MR1", "MR4"]  # Only implemented ones
    else:
        mrs = [mr]

    # Import here to avoid slow startup for --help
    from reflect.core.orchestrator import Orchestrator

    # Create orchestrator and run tests
    orchestrator = Orchestrator(
        avd_name=avd,
        headless=headless
    )

    # Check prerequisites
    prereqs = orchestrator.check_prerequisites()
    missing = [name for name, available in prereqs.items() if not available]
    
    if missing:
        console.print("[red]Error:[/red] Missing prerequisites:")
        for name in missing:
            console.print(f"  • {name}")
        console.print("\nRun [cyan]reflect info[/cyan] for more details.")
        raise SystemExit(1)

    # Run tests
    try:
        session = orchestrator.run_all_tests(
            app_path=apk,
            mrs=mrs
        )

        # Generate report if requested
        if report == "html":
            report_path = generate_html_report(session)
            console.print(f"\n📄 Report saved to: [cyan]{report_path}[/cyan]")
        elif report == "json":
            report_path = generate_json_report(session)
            console.print(f"\n📄 Report saved to: [cyan]{report_path}[/cyan]")

        # Exit with error code if vulnerabilities found
        if session.vulnerabilities_found > 0:
            raise SystemExit(1)

    except KeyboardInterrupt:
        console.print("\n[yellow]Test interrupted by user[/yellow]")
        orchestrator.teardown()
        raise SystemExit(130)
    except Exception as e:
        console.print(f"\n[red]Error:[/red] {e}")
        raise SystemExit(1)


@cli.command(name="list")
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


@cli.command()
def info():
    """
    Show information about the testing environment.
    """
    console.print("\n[bold blue]📋 Environment Information[/bold blue]\n")

    # Check Python
    import sys
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    console.print(f"  ✅ Python: {python_version}")

    # Check Android SDK
    from reflect.emulator.android import check_environment
    env = check_environment()
    
    if env.get("adb") == "installed":
        console.print("  ✅ ADB: Installed")
    else:
        console.print("  ❌ ADB: Not found")
        console.print("     [dim]Install Android SDK or set ANDROID_HOME[/dim]")

    if env.get("emulator") == "installed":
        console.print("  ✅ Emulator: Installed")
    else:
        console.print("  ❌ Emulator: Not found")

    # Check AVDs
    avds = env.get("avds", [])
    if isinstance(avds, list) and avds:
        console.print(f"  ✅ AVDs: {', '.join(avds)}")
    else:
        console.print("  ⚠️  AVDs: None created")
        console.print("     [dim]Create with: avdmanager create avd -n reflect-test -k <system-image>[/dim]")

    # Check running devices
    devices = env.get("running_devices", [])
    if isinstance(devices, list) and devices:
        console.print(f"  ℹ️  Running devices: {', '.join(devices)}")
    else:
        console.print("  ℹ️  Running devices: None")

    # Check mitmproxy
    from reflect.proxy.controller import check_mitmproxy_installed
    if check_mitmproxy_installed():
        console.print("  ✅ mitmproxy: Installed")
    else:
        console.print("  ❌ mitmproxy: Not found")
        console.print("     [dim]Install with: pip install mitmproxy[/dim]")

    # Check Maestro
    from reflect.maestro.runner import check_maestro_installed, get_maestro_version
    if check_maestro_installed():
        version = get_maestro_version() or "unknown"
        console.print(f"  ✅ Maestro: {version}")
    else:
        console.print("  ❌ Maestro: Not found")
        console.print("     [dim]Install from: https://maestro.mobile.dev[/dim]")

    # Check Docker (optional, for future use)
    import subprocess
    try:
        result = subprocess.run(["docker", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            version = result.stdout.strip().split(",")[0]
            console.print(f"  ✅ Docker: {version}")
        else:
            console.print("  ⚠️  Docker: Not running")
    except FileNotFoundError:
        console.print("  ⚠️  Docker: Not found (optional)")

    console.print()


@cli.command()
@click.option(
    "--name",
    default="reflect-test",
    help="Name for the AVD (default: reflect-test)",
)
def setup_avd(name):
    """
    Create an Android Virtual Device for testing.
    """
    import subprocess

    console.print(f"\n[bold blue]Creating AVD: {name}[/bold blue]\n")

    # Find available system image
    try:
        result = subprocess.run(
            ["sdkmanager", "--list"],
            capture_output=True,
            text=True
        )
        
        # Look for arm64 image (for Apple Silicon) or x86_64
        import platform
        arch = platform.machine()
        
        if arch == "arm64":
            image_pattern = "arm64-v8a"
        else:
            image_pattern = "x86_64"
        
        # Find a suitable image
        available_images = []
        for line in result.stdout.split("\n"):
            if "system-images" in line and image_pattern in line and "google" in line:
                parts = line.strip().split("|")
                if parts:
                    available_images.append(parts[0].strip())
        
        if not available_images:
            console.print("[red]Error:[/red] No suitable system image found.")
            console.print(f"Install one with: [cyan]sdkmanager 'system-images;android-34;google_atd;{image_pattern}'[/cyan]")
            raise SystemExit(1)
        
        # Use the first available image
        system_image = available_images[0]
        console.print(f"  Using image: [cyan]{system_image}[/cyan]")
        
        # Create AVD
        result = subprocess.run(
            [
                "avdmanager", "create", "avd",
                "-n", name,
                "-k", system_image,
                "-d", "pixel_6",
                "--force"
            ],
            capture_output=True,
            text=True,
            input="no\n"  # Don't create custom hardware profile
        )
        
        if result.returncode == 0:
            console.print(f"\n  ✅ AVD '{name}' created successfully!")
            console.print(f"\n  Start with: [cyan]emulator -avd {name}[/cyan]")
        else:
            console.print(f"[red]Error:[/red] {result.stderr}")
            raise SystemExit(1)
            
    except FileNotFoundError:
        console.print("[red]Error:[/red] Android SDK tools not found.")
        console.print("Make sure ANDROID_HOME is set correctly.")
        raise SystemExit(1)

    console.print()


def generate_html_report(session) -> Path:
    """
    Generate HTML report from test session.
    
    Args:
        session: TestSession with results
        
    Returns:
        Path to the generated report
    """
    from datetime import datetime
    
    report_dir = Path("reports")
    report_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = report_dir / f"reflect_report_{timestamp}.html"
    
    # Generate HTML content
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Reflect Security Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; }}
        h1 {{ color: #2563eb; }}
        .summary {{ background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .passed {{ color: #059669; }}
        .failed {{ color: #dc2626; }}
        .vulnerable {{ background: #fef2f2; border-left: 4px solid #dc2626; padding: 10px; margin: 10px 0; }}
        .secure {{ background: #f0fdf4; border-left: 4px solid #059669; padding: 10px; margin: 10px 0; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #e5e7eb; padding: 12px; text-align: left; }}
        th {{ background: #f9fafb; }}
    </style>
</head>
<body>
    <h1>🔍 Reflect Security Report</h1>
    
    <div class="summary">
        <p><strong>App:</strong> {session.app_path}</p>
        <p><strong>Platform:</strong> {session.platform}</p>
        <p><strong>Duration:</strong> {session.duration:.1f} seconds</p>
        <p><strong>Tests:</strong> {len(session.results)} | 
           <span class="passed">Passed: {session.passed_count}</span> | 
           <span class="failed">Failed: {session.failed_count}</span></p>
        <p><strong>Vulnerabilities Found:</strong> <span class="failed">{session.vulnerabilities_found}</span></p>
    </div>
    
    <h2>Test Results</h2>
    <table>
        <tr>
            <th>MR ID</th>
            <th>Status</th>
            <th>Vulnerable</th>
            <th>Details</th>
            <th>Duration</th>
        </tr>
"""
    
    for result in session.results:
        status_class = "passed" if result.passed else "failed"
        status_text = "PASSED" if result.passed else "FAILED"
        vuln_text = "YES" if result.vulnerable else "NO"
        vuln_class = "failed" if result.vulnerable else "passed"
        
        html += f"""        <tr>
            <td>{result.mr_id}</td>
            <td class="{status_class}">{status_text}</td>
            <td class="{vuln_class}">{vuln_text}</td>
            <td>{result.comparison_details or result.error or '-'}</td>
            <td>{result.duration_seconds:.1f}s</td>
        </tr>
"""
    
    html += """    </table>
</body>
</html>
"""
    
    report_path.write_text(html)
    return report_path


def generate_json_report(session) -> Path:
    """
    Generate JSON report from test session.
    
    Args:
        session: TestSession with results
        
    Returns:
        Path to the generated report
    """
    import json
    from datetime import datetime
    
    report_dir = Path("reports")
    report_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = report_dir / f"reflect_report_{timestamp}.json"
    
    report_data = {
        "app_path": session.app_path,
        "platform": session.platform,
        "started_at": session.started_at,
        "ended_at": session.ended_at,
        "duration_seconds": session.duration,
        "summary": {
            "total_tests": len(session.results),
            "passed": session.passed_count,
            "failed": session.failed_count,
            "vulnerabilities_found": session.vulnerabilities_found
        },
        "results": [
            {
                "mr_id": r.mr_id,
                "passed": r.passed,
                "vulnerable": r.vulnerable,
                "source_result": r.source_result,
                "followup_result": r.followup_result,
                "comparison_details": r.comparison_details,
                "duration_seconds": r.duration_seconds,
                "error": r.error
            }
            for r in session.results
        ]
    }
    
    report_path.write_text(json.dumps(report_data, indent=2))
    return report_path


# Entry point when running with: python -m reflect
if __name__ == "__main__":
    cli()