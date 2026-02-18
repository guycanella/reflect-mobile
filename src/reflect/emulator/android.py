"""
Android emulator controller for Reflect.

Handles AVD management, emulator lifecycle, and device configuration.
"""

import subprocess
import time
import re
from typing import Optional
from dataclasses import dataclass


@dataclass
class EmulatorStatus:
    """Status of an Android emulator instance."""
    running: bool
    device_id: Optional[str] = None
    avd_name: Optional[str] = None


class AndroidEmulator:
    """
    Controls Android emulator for security testing.
    
    Provides methods to start/stop emulator, install apps,
    and configure proxy settings for traffic interception.
    """
    
    def __init__(self, avd_name: str = "reflect-test"):
        """
        Initialize emulator controller.
        
        Args:
            avd_name: Name of the AVD to use (default: reflect-test)
        """
        self.avd_name = avd_name
        self._emulator_process: Optional[subprocess.Popen] = None
        self._device_id: Optional[str] = None
    
    @staticmethod
    def list_avds() -> list[str]:
        """
        List all available Android Virtual Devices.
        
        Returns:
            List of AVD names
        """
        try:
            result = subprocess.run(
                ["emulator", "-list-avds"],
                capture_output=True,
                text=True,
                check=True
            )
            avds = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
            return avds
        except subprocess.CalledProcessError:
            return []
        except FileNotFoundError:
            raise RuntimeError("Android emulator not found. Is ANDROID_HOME configured?")
    
    @staticmethod
    def list_running_devices() -> list[str]:
        """
        List all connected/running Android devices.
        
        Returns:
            List of device IDs (e.g., ['emulator-5554'])
        """
        try:
            result = subprocess.run(
                ["adb", "devices"],
                capture_output=True,
                text=True,
                check=True
            )
            devices = []
            for line in result.stdout.strip().split("\n")[1:]:  # Skip header
                if "\tdevice" in line:
                    device_id = line.split("\t")[0]
                    devices.append(device_id)
            return devices
        except subprocess.CalledProcessError:
            return []
    
    def get_status(self) -> EmulatorStatus:
        """
        Get current emulator status.
        
        Returns:
            EmulatorStatus with running state and device info
        """
        devices = self.list_running_devices()
        
        if not devices:
            return EmulatorStatus(running=False)
        
        # Check if our AVD is running
        for device_id in devices:
            avd = self._get_device_avd_name(device_id)
            if avd == self.avd_name:
                self._device_id = device_id
                return EmulatorStatus(
                    running=True,
                    device_id=device_id,
                    avd_name=avd
                )
        
        # Some emulator is running but not ours
        return EmulatorStatus(
            running=True,
            device_id=devices[0],
            avd_name=self._get_device_avd_name(devices[0])
        )
    
    def _get_device_avd_name(self, device_id: str) -> Optional[str]:
        """
        Get AVD name for a running device.
        
        Args:
            device_id: Device ID (e.g., emulator-5554)
            
        Returns:
            AVD name or None if not found
        """
        try:
            result = subprocess.run(
                ["adb", "-s", device_id, "emu", "avd", "name"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Output format: "avd_name\nOK"
                return result.stdout.strip().split("\n")[0]
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        return None
    
    def start(self, headless: bool = False, proxy_port: Optional[int] = None) -> str:
        """
        Start the Android emulator.
        
        Args:
            headless: Run without GUI window (for CI/CD)
            proxy_port: Port for HTTP proxy (e.g., 8080 for mitmproxy)
            
        Returns:
            Device ID of the started emulator
            
        Raises:
            RuntimeError: If emulator fails to start
        """
        # Check if already running
        status = self.get_status()
        if status.running and status.avd_name == self.avd_name:
            self._device_id = status.device_id
            return status.device_id
        
        # Verify AVD exists
        if self.avd_name not in self.list_avds():
            raise RuntimeError(f"AVD '{self.avd_name}' not found. Available: {self.list_avds()}")
        
        # Build emulator command
        cmd = ["emulator", "-avd", self.avd_name]
        
        if headless:
            cmd.extend(["-no-window", "-no-audio"])
        
        if proxy_port:
            cmd.extend(["-http-proxy", f"http://127.0.0.1:{proxy_port}"])
        
        # Reduce resource usage
        cmd.extend(["-no-snapshot-save", "-no-boot-anim"])
        
        # Start emulator in background
        self._emulator_process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        # Wait for device to be ready
        if not self._wait_for_boot(timeout=120):
            self.stop()
            raise RuntimeError("Emulator failed to boot within timeout")
        
        # Get device ID
        devices = self.list_running_devices()
        if devices:
            self._device_id = devices[0]
            return self._device_id
        
        raise RuntimeError("Emulator started but no device found")
    
    def _wait_for_boot(self, timeout: int = 120) -> bool:
        """
        Wait for emulator to fully boot.
        
        Args:
            timeout: Maximum seconds to wait
            
        Returns:
            True if booted successfully, False otherwise
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                # Check if device is visible
                devices = self.list_running_devices()
                if not devices:
                    time.sleep(2)
                    continue
                
                # Check boot completion
                result = subprocess.run(
                    ["adb", "-s", devices[0], "shell", "getprop", "sys.boot_completed"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.stdout.strip() == "1":
                    # Give it a bit more time to stabilize
                    time.sleep(3)
                    return True
                    
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
            
            time.sleep(2)
        
        return False
    
    def stop(self) -> None:
        """Stop the emulator."""
        if self._device_id:
            try:
                subprocess.run(
                    ["adb", "-s", self._device_id, "emu", "kill"],
                    capture_output=True,
                    timeout=10
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
        
        if self._emulator_process:
            self._emulator_process.terminate()
            try:
                self._emulator_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._emulator_process.kill()
            self._emulator_process = None
        
        self._device_id = None
    
    def install_apk(self, apk_path: str) -> None:
        """
        Install an APK on the emulator.
        
        Args:
            apk_path: Path to the APK file
            
        Raises:
            RuntimeError: If installation fails
        """
        if not self._device_id:
            raise RuntimeError("Emulator not running. Call start() first.")
        
        try:
            result = subprocess.run(
                ["adb", "-s", self._device_id, "install", "-r", "-g", apk_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if "Success" not in result.stdout:
                raise RuntimeError(f"APK installation failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            raise RuntimeError("APK installation timed out")
    
    def uninstall_app(self, package_name: str) -> None:
        """
        Uninstall an app from the emulator.
        
        Args:
            package_name: App package name (e.g., com.example.app)
        """
        if not self._device_id:
            return
        
        try:
            subprocess.run(
                ["adb", "-s", self._device_id, "uninstall", package_name],
                capture_output=True,
                timeout=30
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass  # Ignore if app wasn't installed
    
    def set_proxy(self, host: str = "127.0.0.1", port: int = 8080) -> None:
        """
        Configure HTTP proxy on the emulator.
        
        This routes all HTTP/HTTPS traffic through the proxy (mitmproxy).
        
        Args:
            host: Proxy host address
            port: Proxy port
        """
        if not self._device_id:
            raise RuntimeError("Emulator not running. Call start() first.")
        
        # Set global proxy
        subprocess.run(
            ["adb", "-s", self._device_id, "shell", "settings", "put", "global", 
             "http_proxy", f"{host}:{port}"],
            capture_output=True,
            check=True
        )
    
    def clear_proxy(self) -> None:
        """Remove proxy configuration from the emulator."""
        if not self._device_id:
            return
        
        subprocess.run(
            ["adb", "-s", self._device_id, "shell", "settings", "put", "global", 
             "http_proxy", ":0"],
            capture_output=True
        )
    
    def install_certificate(self, cert_path: str) -> None:
        """
        Install a CA certificate on the emulator.
        
        Required for mitmproxy to intercept HTTPS traffic.
        
        Args:
            cert_path: Path to the certificate file (.pem or .cer)
        """
        if not self._device_id:
            raise RuntimeError("Emulator not running. Call start() first.")
        
        # Get certificate hash for Android naming convention
        cert_hash = self._get_cert_hash(cert_path)
        
        # Push certificate to device
        remote_path = f"/sdcard/{cert_hash}.0"
        subprocess.run(
            ["adb", "-s", self._device_id, "push", cert_path, remote_path],
            capture_output=True,
            check=True
        )
        
        # Move to system certificate store (requires root)
        commands = [
            "su -c 'mount -o rw,remount /system'",
            f"su -c 'cp {remote_path} /system/etc/security/cacerts/{cert_hash}.0'",
            f"su -c 'chmod 644 /system/etc/security/cacerts/{cert_hash}.0'",
            f"rm {remote_path}"
        ]
        
        for cmd in commands:
            subprocess.run(
                ["adb", "-s", self._device_id, "shell", cmd],
                capture_output=True
            )
    
    def _get_cert_hash(self, cert_path: str) -> str:
        """
        Get OpenSSL subject hash for certificate naming.
        
        Args:
            cert_path: Path to certificate file
            
        Returns:
            Certificate hash string
        """
        try:
            result = subprocess.run(
                ["openssl", "x509", "-inform", "PEM", "-subject_hash_old", 
                 "-in", cert_path, "-noout"],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            # Fallback: use simple hash
            return "9a5ba575"  # Default mitmproxy cert hash
    
    def take_screenshot(self, output_path: str) -> None:
        """
        Take a screenshot of the emulator.
        
        Useful for debugging test failures.
        
        Args:
            output_path: Where to save the screenshot
        """
        if not self._device_id:
            raise RuntimeError("Emulator not running")
        
        # Capture on device
        subprocess.run(
            ["adb", "-s", self._device_id, "shell", "screencap", "-p", "/sdcard/screen.png"],
            capture_output=True,
            check=True
        )
        
        # Pull to local machine
        subprocess.run(
            ["adb", "-s", self._device_id, "pull", "/sdcard/screen.png", output_path],
            capture_output=True,
            check=True
        )
        
        # Cleanup
        subprocess.run(
            ["adb", "-s", self._device_id, "shell", "rm", "/sdcard/screen.png"],
            capture_output=True
        )
    
    def get_installed_packages(self) -> list[str]:
        """
        List all installed packages on the emulator.
        
        Returns:
            List of package names
        """
        if not self._device_id:
            return []
        
        try:
            result = subprocess.run(
                ["adb", "-s", self._device_id, "shell", "pm", "list", "packages"],
                capture_output=True,
                text=True,
                check=True
            )
            
            packages = []
            for line in result.stdout.strip().split("\n"):
                if line.startswith("package:"):
                    packages.append(line.replace("package:", ""))
            return packages
            
        except subprocess.CalledProcessError:
            return []


def check_environment() -> dict:
    """
    Check if Android development environment is properly configured.
    
    Returns:
        Dict with status of each component
    """
    status = {}
    
    # Check adb
    try:
        result = subprocess.run(["adb", "version"], capture_output=True, text=True)
        status["adb"] = "installed" if result.returncode == 0 else "error"
    except FileNotFoundError:
        status["adb"] = "not found"
    
    # Check emulator
    try:
        result = subprocess.run(["emulator", "-version"], capture_output=True, text=True)
        status["emulator"] = "installed" if result.returncode == 0 else "error"
    except FileNotFoundError:
        status["emulator"] = "not found"
    
    # Check AVDs
    try:
        avds = AndroidEmulator.list_avds()
        status["avds"] = avds if avds else "none created"
    except RuntimeError:
        status["avds"] = "error"
    
    # Check running devices
    devices = AndroidEmulator.list_running_devices()
    status["running_devices"] = devices if devices else "none"
    
    return status