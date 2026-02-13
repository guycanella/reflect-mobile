"""
Test orchestrator for Reflect.

Coordinates emulator, proxy, and Maestro to execute metamorphic security tests.
"""

import time
from typing import Optional
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from reflect.emulator.android import AndroidEmulator, check_environment
from reflect.proxy.controller import MitmproxyController, ProxyMode, check_mitmproxy_installed
from reflect.maestro.runner import MaestroRunner, FlowResult, check_maestro_installed


console = Console()


class TestPhase(Enum):
    """Phases of a metamorphic test."""
    SETUP = "setup"
    SOURCE_TEST = "source_test"      # STC: Normal execution
    FOLLOWUP_TEST = "followup_test"  # FUTC: Altered conditions
    COMPARISON = "comparison"
    CLEANUP = "cleanup"


@dataclass
class MRTestResult:
    """Result of a Metamorphic Relation test."""
    mr_id: str
    passed: bool
    vulnerable: bool
    source_result: Optional[dict] = None
    followup_result: Optional[dict] = None
    comparison_details: str = ""
    duration_seconds: float = 0
    error: Optional[str] = None


@dataclass
class TestSession:
    """A complete test session with all MR results."""
    app_path: str
    platform: str
    started_at: float = field(default_factory=time.time)
    ended_at: Optional[float] = None
    results: list[MRTestResult] = field(default_factory=list)
    
    @property
    def duration(self) -> float:
        if self.ended_at:
            return self.ended_at - self.started_at
        return time.time() - self.started_at
    
    @property
    def passed_count(self) -> int:
        return sum(1 for r in self.results if r.passed)
    
    @property
    def failed_count(self) -> int:
        return sum(1 for r in self.results if not r.passed)
    
    @property
    def vulnerabilities_found(self) -> int:
        return sum(1 for r in self.results if r.vulnerable)


class Orchestrator:
    """
    Coordinates all components to execute metamorphic security tests.
    
    Test flow:
    1. Start emulator with proxy configured
    2. Install app
    3. For each MR:
       a. Execute Source Test Case (normal conditions)
       b. Execute Follow-up Test Case (altered conditions)
       c. Compare results using Metamorphic Relation
    4. Generate report
    """
    
    def __init__(
        self,
        avd_name: str = "reflect-test",
        proxy_port: int = 8080,
        headless: bool = False
    ):
        """
        Initialize orchestrator.
        
        Args:
            avd_name: Android Virtual Device name
            proxy_port: Port for mitmproxy
            headless: Run emulator without GUI
        """
        self.emulator = AndroidEmulator(avd_name)
        self.proxy = MitmproxyController(proxy_port)
        self.maestro = MaestroRunner()
        self.headless = headless
        
        self._session: Optional[TestSession] = None
        self._app_package: Optional[str] = None
    
    def check_prerequisites(self) -> dict[str, bool]:
        """
        Verify all required tools are installed.
        
        Returns:
            Dict with tool names and their availability
        """
        return {
            "android_sdk": check_environment().get("adb") == "installed",
            "emulator": check_environment().get("emulator") == "installed",
            "avd_exists": self.emulator.avd_name in self.emulator.list_avds(),
            "mitmproxy": check_mitmproxy_installed(),
            "maestro": check_maestro_installed()
        }
    
    def setup(self, app_path: str) -> None:
        """
        Set up test environment.
        
        Args:
            app_path: Path to APK or IPA file
            
        Raises:
            RuntimeError: If setup fails
        """
        app_path = Path(app_path)
        if not app_path.exists():
            raise RuntimeError(f"App not found: {app_path}")
        
        platform = "android" if app_path.suffix == ".apk" else "ios"
        self._session = TestSession(app_path=str(app_path), platform=platform)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            # Start proxy
            task = progress.add_task("Starting mitmproxy...", total=None)
            self.proxy.clear_results()
            self.proxy.start(ProxyMode.PASSTHROUGH)
            progress.update(task, description="✓ Mitmproxy started")
            
            # Start emulator with proxy
            task = progress.add_task("Starting emulator...", total=None)
            device_id = self.emulator.start(
                headless=self.headless,
                proxy_port=self.proxy.port
            )
            self.maestro.set_device(device_id)
            progress.update(task, description=f"✓ Emulator started ({device_id})")
            
            # Install mitmproxy certificate
            task = progress.add_task("Installing proxy certificate...", total=None)
            try:
                cert_path = self.proxy.get_certificate_path()
                self.emulator.install_certificate(str(cert_path))
                progress.update(task, description="✓ Certificate installed")
            except Exception as e:
                progress.update(task, description=f"⚠ Certificate install failed: {e}")
            
            # Install app
            task = progress.add_task("Installing app...", total=None)
            self.emulator.install_apk(str(app_path))
            self._app_package = self._get_package_name(app_path)
            progress.update(task, description=f"✓ App installed ({self._app_package})")
    
    def _get_package_name(self, apk_path: Path) -> str:
        """
        Extract package name from APK.
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            Package name string
        """
        import subprocess
        
        try:
            result = subprocess.run(
                ["aapt", "dump", "badging", str(apk_path)],
                capture_output=True,
                text=True
            )
            
            for line in result.stdout.split("\n"):
                if line.startswith("package:"):
                    # Extract name='com.example.app'
                    import re
                    match = re.search(r"name='([^']+)'", line)
                    if match:
                        return match.group(1)
        except FileNotFoundError:
            pass
        
        # Fallback: use filename
        return apk_path.stem
    
    def teardown(self) -> None:
        """Clean up test environment."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            task = progress.add_task("Stopping emulator...", total=None)
            self.emulator.stop()
            progress.update(task, description="✓ Emulator stopped")
            
            task = progress.add_task("Stopping proxy...", total=None)
            self.proxy.stop()
            progress.update(task, description="✓ Proxy stopped")
        
        if self._session:
            self._session.ended_at = time.time()
    
    def run_mr1_certificate_validation(
        self,
        login_flow_path: Optional[Path] = None
    ) -> MRTestResult:
        """
        Execute MR1: SSL Certificate Validation test.
        
        Tests if the app properly rejects invalid/self-signed certificates.
        
        MR1: If login succeeds normally (STC), then with an invalid
        certificate (FUTC), the app should show an error.
        
        Args:
            login_flow_path: Path to Maestro login flow
            
        Returns:
            MRTestResult with pass/fail status
        """
        start_time = time.time()
        mr_id = "MR1"
        
        console.print(f"\n[bold cyan]Testing {mr_id}: Certificate Validation[/bold cyan]")
        console.print("  CWE-295: Improper Certificate Validation\n")
        
        try:
            # Generate default login flow if not provided
            if not login_flow_path and self._app_package:
                flow_content = self.maestro.generate_login_flow(self._app_package)
                login_flow_path = self.maestro.save_flow(flow_content, "mr1_login")
            
            # === Source Test Case (STC) ===
            console.print("  [dim]Phase 1: Source Test (normal conditions)[/dim]")
            self.proxy.stop()
            self.proxy.start(ProxyMode.PASSTHROUGH)
            
            stc_result = self.maestro.run_flow(login_flow_path)
            stc_passed = stc_result.result == FlowResult.PASSED
            
            if not stc_passed:
                return MRTestResult(
                    mr_id=mr_id,
                    passed=False,
                    vulnerable=False,
                    source_result={"flow_result": stc_result.result.value},
                    error="Source test failed - login flow did not succeed",
                    duration_seconds=time.time() - start_time
                )
            
            console.print("    ✓ Login succeeded under normal conditions")
            
            # === Follow-up Test Case (FUTC) ===
            console.print("  [dim]Phase 2: Follow-up Test (invalid certificate)[/dim]")
            
            # Restart proxy in certificate rejection mode
            self.proxy.stop()
            self.proxy.start(ProxyMode.REJECT_INVALID_CERT)
            
            # Clear app state and retry login
            self._clear_app_state()
            
            futc_result = self.maestro.run_flow(login_flow_path)
            
            # Check if app accepted the invalid certificate
            mr1_result = self.proxy.get_mr1_result()
            
            # === Comparison (Metamorphic Relation) ===
            console.print("  [dim]Phase 3: Comparing results[/dim]")
            
            # MR1: If STC succeeds, FUTC should FAIL (show error)
            # If FUTC also succeeds, app is VULNERABLE
            vulnerable = False
            comparison = ""
            
            if mr1_result and mr1_result.get("vulnerable"):
                vulnerable = True
                comparison = "VULNERABLE: App accepted invalid certificate and completed login"
            elif futc_result.result == FlowResult.PASSED:
                vulnerable = True
                comparison = "VULNERABLE: Login succeeded with invalid certificate"
            else:
                comparison = "SECURE: App rejected invalid certificate"
            
            passed = not vulnerable
            
            if vulnerable:
                console.print(f"    [red]✗ {comparison}[/red]")
            else:
                console.print(f"    [green]✓ {comparison}[/green]")
            
            return MRTestResult(
                mr_id=mr_id,
                passed=passed,
                vulnerable=vulnerable,
                source_result={"flow_result": stc_result.result.value},
                followup_result={
                    "flow_result": futc_result.result.value,
                    "proxy_detected": mr1_result
                },
                comparison_details=comparison,
                duration_seconds=time.time() - start_time
            )
            
        except Exception as e:
            return MRTestResult(
                mr_id=mr_id,
                passed=False,
                vulnerable=False,
                error=str(e),
                duration_seconds=time.time() - start_time
            )
    
    def run_mr4_encryption(
        self,
        login_flow_path: Optional[Path] = None
    ) -> MRTestResult:
        """
        Execute MR4: Data Encryption test.
        
        Tests if the app refuses to send credentials over HTTP.
        
        MR4: If login succeeds over HTTPS (STC), then when forced
        to HTTP (FUTC), the app should refuse to send credentials.
        
        Args:
            login_flow_path: Path to Maestro login flow
            
        Returns:
            MRTestResult with pass/fail status
        """
        start_time = time.time()
        mr_id = "MR4"
        
        console.print(f"\n[bold cyan]Testing {mr_id}: Data Encryption[/bold cyan]")
        console.print("  CWE-311: Missing Encryption of Sensitive Data\n")
        
        try:
            # Generate default login flow if not provided
            if not login_flow_path and self._app_package:
                flow_content = self.maestro.generate_login_flow(self._app_package)
                login_flow_path = self.maestro.save_flow(flow_content, "mr4_login")
            
            # === Source Test Case (STC) ===
            console.print("  [dim]Phase 1: Source Test (HTTPS)[/dim]")
            self.proxy.stop()
            self.proxy.start(ProxyMode.PASSTHROUGH)
            
            stc_result = self.maestro.run_flow(login_flow_path)
            stc_passed = stc_result.result == FlowResult.PASSED
            
            if not stc_passed:
                return MRTestResult(
                    mr_id=mr_id,
                    passed=False,
                    vulnerable=False,
                    source_result={"flow_result": stc_result.result.value},
                    error="Source test failed - login flow did not succeed",
                    duration_seconds=time.time() - start_time
                )
            
            console.print("    ✓ Login succeeded over HTTPS")
            
            # === Follow-up Test Case (FUTC) ===
            console.print("  [dim]Phase 2: Follow-up Test (HTTP downgrade)[/dim]")
            
            # Restart proxy in HTTP downgrade mode
            self.proxy.stop()
            self.proxy.start(ProxyMode.FORCE_HTTP)
            
            # Clear app state and retry login
            self._clear_app_state()
            
            futc_result = self.maestro.run_flow(login_flow_path)
            
            # Check if credentials were sent over HTTP
            mr4_result = self.proxy.get_mr4_result()
            
            # === Comparison (Metamorphic Relation) ===
            console.print("  [dim]Phase 3: Comparing results[/dim]")
            
            # MR4: If STC succeeds over HTTPS, FUTC should FAIL over HTTP
            # If credentials are sent over HTTP, app is VULNERABLE
            vulnerable = False
            comparison = ""
            
            if mr4_result and mr4_result.get("vulnerable"):
                vulnerable = True
                credentials_count = mr4_result.get("credentials_exposed", 0)
                comparison = f"VULNERABLE: Credentials sent over HTTP ({credentials_count} requests)"
            elif futc_result.result == FlowResult.PASSED:
                vulnerable = True
                comparison = "VULNERABLE: Login succeeded over HTTP"
            else:
                comparison = "SECURE: App refused to send credentials over HTTP"
            
            passed = not vulnerable
            
            if vulnerable:
                console.print(f"    [red]✗ {comparison}[/red]")
            else:
                console.print(f"    [green]✓ {comparison}[/green]")
            
            return MRTestResult(
                mr_id=mr_id,
                passed=passed,
                vulnerable=vulnerable,
                source_result={"flow_result": stc_result.result.value},
                followup_result={
                    "flow_result": futc_result.result.value,
                    "proxy_detected": mr4_result
                },
                comparison_details=comparison,
                duration_seconds=time.time() - start_time
            )
            
        except Exception as e:
            return MRTestResult(
                mr_id=mr_id,
                passed=False,
                vulnerable=False,
                error=str(e),
                duration_seconds=time.time() - start_time
            )
    
    def _clear_app_state(self) -> None:
        """Clear app data to ensure clean state between tests."""
        if not self._app_package:
            return
        
        import subprocess
        
        device_id = self.emulator._device_id
        if device_id:
            subprocess.run(
                ["adb", "-s", device_id, "shell", "pm", "clear", self._app_package],
                capture_output=True
            )
    
    def run_all_tests(
        self,
        app_path: str,
        mrs: Optional[list[str]] = None
    ) -> TestSession:
        """
        Run all specified MR tests.
        
        Args:
            app_path: Path to APK or IPA
            mrs: List of MR IDs to run (default: all available)
            
        Returns:
            TestSession with all results
        """
        if mrs is None:
            mrs = ["MR1", "MR4"]  # Only implemented MRs for now
        
        console.print("\n[bold blue]🔍 Reflect Security Test[/bold blue]")
        console.print(f"  App: [cyan]{app_path}[/cyan]")
        console.print(f"  Tests: [cyan]{', '.join(mrs)}[/cyan]\n")
        
        # Setup
        self.setup(app_path)
        
        try:
            # Run each MR
            for mr_id in mrs:
                if mr_id == "MR1":
                    result = self.run_mr1_certificate_validation()
                elif mr_id == "MR4":
                    result = self.run_mr4_encryption()
                else:
                    console.print(f"[yellow]⚠ {mr_id} not yet implemented[/yellow]")
                    continue
                
                self._session.results.append(result)
            
            # Summary
            self._print_summary()
            
        finally:
            self.teardown()
        
        return self._session
    
    def _print_summary(self) -> None:
        """Print test session summary."""
        if not self._session:
            return
        
        console.print("\n" + "=" * 50)
        console.print("[bold]Test Summary[/bold]")
        console.print("=" * 50)
        
        for result in self._session.results:
            status = "[green]PASSED[/green]" if result.passed else "[red]FAILED[/red]"
            vuln = " [red](VULNERABLE)[/red]" if result.vulnerable else ""
            console.print(f"  {result.mr_id}: {status}{vuln}")
            if result.comparison_details:
                console.print(f"    [dim]{result.comparison_details}[/dim]")
        
        console.print()
        console.print(f"  Total: {len(self._session.results)} tests")
        console.print(f"  Passed: [green]{self._session.passed_count}[/green]")
        console.print(f"  Failed: [red]{self._session.failed_count}[/red]")
        console.print(f"  Vulnerabilities: [red]{self._session.vulnerabilities_found}[/red]")
        console.print(f"  Duration: {self._session.duration:.1f}s")
        console.print()