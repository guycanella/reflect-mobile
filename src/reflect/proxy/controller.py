"""
Mitmproxy controller for Reflect.

Handles traffic interception, certificate manipulation, and token capture
for metamorphic security testing.
"""

import subprocess
import time
import json
from typing import Optional
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum


class ProxyMode(Enum):
    """Proxy operation modes for different MR tests."""
    PASSTHROUGH = "passthrough"      # Normal traffic, just observe
    REJECT_INVALID_CERT = "reject"   # MR1: Reject if app accepts bad certs
    FORCE_HTTP = "http"              # MR4: Downgrade HTTPS to HTTP
    CAPTURE_TOKENS = "capture"       # MR2/MR3: Capture Access Tokens


@dataclass
class CapturedToken:
    """Represents a captured authentication token."""
    token: str
    token_type: str  # "bearer", "session", etc.
    endpoint: str
    timestamp: float
    headers: dict = field(default_factory=dict)


@dataclass 
class ProxyStatus:
    """Status of the mitmproxy instance."""
    running: bool
    port: int = 8080
    mode: ProxyMode = ProxyMode.PASSTHROUGH
    pid: Optional[int] = None


class MitmproxyController:
    """
    Controls mitmproxy for security testing.
    
    Supports different modes for testing various vulnerabilities:
    - Certificate validation (MR1)
    - Encryption requirements (MR4)
    - Token capture for session testing (MR2, MR3)
    """
    
    DEFAULT_PORT = 8080
    CERTS_DIR = Path.home() / ".mitmproxy"
    
    def __init__(self, port: int = DEFAULT_PORT):
        """
        Initialize mitmproxy controller.
        
        Args:
            port: Port for proxy to listen on (default: 8080)
        """
        self.port = port
        self._process: Optional[subprocess.Popen] = None
        self._mode: ProxyMode = ProxyMode.PASSTHROUGH
        self._captured_tokens: list[CapturedToken] = []
        self._script_path: Optional[Path] = None
    
    def get_status(self) -> ProxyStatus:
        """
        Get current proxy status.
        
        Returns:
            ProxyStatus with running state and configuration
        """
        running = self._process is not None and self._process.poll() is None
        return ProxyStatus(
            running=running,
            port=self.port,
            mode=self._mode,
            pid=self._process.pid if running else None
        )
    
    def start(self, mode: ProxyMode = ProxyMode.PASSTHROUGH) -> None:
        """
        Start mitmproxy with specified mode.
        
        Args:
            mode: Operation mode for the proxy
            
        Raises:
            RuntimeError: If proxy fails to start
        """
        # Stop existing instance
        if self.get_status().running:
            self.stop()
        
        self._mode = mode
        
        # Build command based on mode
        cmd = ["mitmdump", "-p", str(self.port), "--ssl-insecure"]
        
        # Add mode-specific script
        script_content = self._generate_script(mode)
        if script_content:
            self._script_path = Path("/tmp/reflect_proxy_script.py")
            self._script_path.write_text(script_content)
            cmd.extend(["-s", str(self._script_path)])
        
        # Add mode-specific options
        if mode == ProxyMode.FORCE_HTTP:
            # Strip HTTPS, allow HTTP
            cmd.append("--set")
            cmd.append("upstream_cert=false")
        
        # Start mitmproxy
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for proxy to be ready
            if not self._wait_for_ready(timeout=10):
                self.stop()
                raise RuntimeError("Mitmproxy failed to start")
                
        except FileNotFoundError:
            raise RuntimeError("mitmproxy not found. Install with: pip install mitmproxy")
    
    def _wait_for_ready(self, timeout: int = 10) -> bool:
        """
        Wait for mitmproxy to be ready to accept connections.
        
        Args:
            timeout: Maximum seconds to wait
            
        Returns:
            True if ready, False if timeout
        """
        import socket
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', self.port))
                sock.close()
                if result == 0:
                    return True
            except socket.error:
                pass
            time.sleep(0.5)
        
        return False
    
    def stop(self) -> None:
        """Stop mitmproxy."""
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None
        
        # Cleanup script
        if self._script_path and self._script_path.exists():
            self._script_path.unlink()
            self._script_path = None
        
        self._mode = ProxyMode.PASSTHROUGH
    
    def _generate_script(self, mode: ProxyMode) -> Optional[str]:
        """
        Generate mitmproxy addon script for the specified mode.
        
        Args:
            mode: Proxy operation mode
            
        Returns:
            Python script content or None if no script needed
        """
        if mode == ProxyMode.PASSTHROUGH:
            return None
        
        if mode == ProxyMode.REJECT_INVALID_CERT:
            return self._script_reject_invalid_cert()
        
        if mode == ProxyMode.FORCE_HTTP:
            return self._script_force_http()
        
        if mode == ProxyMode.CAPTURE_TOKENS:
            return self._script_capture_tokens()
        
        return None
    
    def _script_reject_invalid_cert(self) -> str:
        """Script to test if app validates certificates (MR1)."""
        return '''
"""MR1: Test certificate validation - inject invalid certificate."""
from mitmproxy import ctx, http
import json

class InvalidCertInjector:
    """
    Injects responses as if using an invalid certificate.
    
    If the app properly validates certificates, it should reject
    connections and show an error. If vulnerable, it will accept.
    """
    
    def __init__(self):
        self.requests_made = []
    
    def request(self, flow: http.HTTPFlow) -> None:
        # Log all auth-related requests
        if any(kw in flow.request.pretty_url.lower() for kw in 
               ["login", "auth", "token", "signin", "session"]):
            self.requests_made.append({
                "url": flow.request.pretty_url,
                "method": flow.request.method,
                "timestamp": flow.request.timestamp_start
            })
            ctx.log.info(f"Auth request intercepted: {flow.request.pretty_url}")
    
    def response(self, flow: http.HTTPFlow) -> None:
        # Log successful auth responses (indicates vulnerability)
        if flow.response and flow.response.status_code == 200:
            if any(kw in flow.request.pretty_url.lower() for kw in 
                   ["login", "auth", "token", "signin"]):
                ctx.log.warn(f"VULNERABILITY: Auth succeeded with invalid cert!")
                # Write to file for test oracle
                with open("/tmp/reflect_mr1_result.json", "w") as f:
                    json.dump({
                        "vulnerable": True,
                        "url": flow.request.pretty_url,
                        "status": flow.response.status_code
                    }, f)

addons = [InvalidCertInjector()]
'''
    
    def _script_force_http(self) -> str:
        """Script to force HTTP and detect unencrypted credentials (MR4)."""
        return '''
"""MR4: Test encryption requirements - force HTTP downgrade."""
from mitmproxy import ctx, http
import json

class HttpDowngrader:
    """
    Forces HTTPS requests to HTTP to test if app encrypts credentials.
    
    If the app properly requires HTTPS, it should refuse to send
    credentials over HTTP. If vulnerable, credentials will be visible.
    """
    
    def __init__(self):
        self.credentials_captured = []
    
    def request(self, flow: http.HTTPFlow) -> None:
        # Check if credentials are being sent over HTTP
        if flow.request.scheme == "http":
            # Look for credentials in request
            body = flow.request.get_text() or ""
            headers = dict(flow.request.headers)
            
            has_credentials = any([
                "password" in body.lower(),
                "passwd" in body.lower(),
                "secret" in body.lower(),
                "authorization" in str(headers).lower(),
            ])
            
            if has_credentials:
                ctx.log.warn(f"VULNERABILITY: Credentials sent over HTTP!")
                self.credentials_captured.append({
                    "url": flow.request.pretty_url,
                    "method": flow.request.method,
                    "has_password_field": "password" in body.lower()
                })
                
                # Write result for test oracle
                with open("/tmp/reflect_mr4_result.json", "w") as f:
                    json.dump({
                        "vulnerable": True,
                        "credentials_exposed": len(self.credentials_captured),
                        "details": self.credentials_captured
                    }, f)
    
    def responseheaders(self, flow: http.HTTPFlow) -> None:
        # Downgrade HTTPS redirects to HTTP
        if flow.response and flow.response.status_code in [301, 302, 307, 308]:
            location = flow.response.headers.get("Location", "")
            if location.startswith("https://"):
                flow.response.headers["Location"] = location.replace("https://", "http://", 1)
                ctx.log.info(f"Downgraded redirect to HTTP: {location}")

addons = [HttpDowngrader()]
'''
    
    def _script_capture_tokens(self) -> str:
        """Script to capture authentication tokens (MR2/MR3)."""
        return '''
"""MR2/MR3: Capture authentication tokens for session testing."""
from mitmproxy import ctx, http
import json
import re
import time

class TokenCapture:
    """
    Captures authentication tokens from responses.
    
    Used for:
    - MR2: Check if token changes after inactivity
    - MR3: Check if token changes after logout/re-login
    """
    
    TOKEN_FILE = "/tmp/reflect_captured_tokens.json"
    
    def __init__(self):
        self.tokens = []
    
    def response(self, flow: http.HTTPFlow) -> None:
        # Check response headers for tokens
        auth_header = flow.response.headers.get("Authorization", "")
        set_cookie = flow.response.headers.get("Set-Cookie", "")
        
        # Check response body for tokens
        try:
            body = flow.response.get_text() or ""
            body_json = json.loads(body) if body.startswith("{") else {}
        except:
            body_json = {}
        
        token_data = None
        
        # Extract Bearer token from header
        if "bearer" in auth_header.lower():
            token_data = {
                "token": auth_header,
                "type": "bearer_header",
                "source": "response_header"
            }
        
        # Extract token from JSON response
        for key in ["access_token", "token", "accessToken", "auth_token", "jwt"]:
            if key in body_json:
                token_data = {
                    "token": str(body_json[key]),
                    "type": key,
                    "source": "response_body"
                }
                break
        
        # Extract session cookie
        if "session" in set_cookie.lower() or "token" in set_cookie.lower():
            token_data = {
                "token": set_cookie.split(";")[0],
                "type": "session_cookie",
                "source": "set_cookie"
            }
        
        if token_data:
            token_data["url"] = flow.request.pretty_url
            token_data["timestamp"] = time.time()
            self.tokens.append(token_data)
            
            ctx.log.info(f"Token captured: {token_data['type']} from {token_data['url']}")
            
            # Save to file
            with open(self.TOKEN_FILE, "w") as f:
                json.dump(self.tokens, f, indent=2)

addons = [TokenCapture()]
'''
    
    def get_certificate_path(self) -> Path:
        """
        Get path to mitmproxy CA certificate.
        
        Returns:
            Path to the certificate file
            
        Raises:
            RuntimeError: If certificate not found
        """
        cert_path = self.CERTS_DIR / "mitmproxy-ca-cert.pem"
        
        if not cert_path.exists():
            # Generate certificates by starting/stopping mitmproxy
            self.start(ProxyMode.PASSTHROUGH)
            time.sleep(2)
            self.stop()
        
        if not cert_path.exists():
            raise RuntimeError(
                f"Mitmproxy certificate not found at {cert_path}. "
                "Try running 'mitmproxy' manually once to generate certificates."
            )
        
        return cert_path
    
    def get_captured_tokens(self) -> list[dict]:
        """
        Get tokens captured during CAPTURE_TOKENS mode.
        
        Returns:
            List of captured token data
        """
        token_file = Path("/tmp/reflect_captured_tokens.json")
        if token_file.exists():
            try:
                return json.loads(token_file.read_text())
            except json.JSONDecodeError:
                return []
        return []
    
    def get_mr1_result(self) -> Optional[dict]:
        """
        Get result from MR1 (certificate validation) test.
        
        Returns:
            Result dict or None if no result
        """
        result_file = Path("/tmp/reflect_mr1_result.json")
        if result_file.exists():
            try:
                return json.loads(result_file.read_text())
            except json.JSONDecodeError:
                return None
        return None
    
    def get_mr4_result(self) -> Optional[dict]:
        """
        Get result from MR4 (HTTP downgrade) test.
        
        Returns:
            Result dict or None if no result
        """
        result_file = Path("/tmp/reflect_mr4_result.json")
        if result_file.exists():
            try:
                return json.loads(result_file.read_text())
            except json.JSONDecodeError:
                return None
        return None
    
    def clear_results(self) -> None:
        """Clear all captured results and tokens."""
        for f in [
            "/tmp/reflect_mr1_result.json",
            "/tmp/reflect_mr4_result.json",
            "/tmp/reflect_captured_tokens.json"
        ]:
            path = Path(f)
            if path.exists():
                path.unlink()
        
        self._captured_tokens = []


def check_mitmproxy_installed() -> bool:
    """
    Check if mitmproxy is installed and accessible.
    
    Returns:
        True if installed, False otherwise
    """
    try:
        result = subprocess.run(
            ["mitmdump", "--version"],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False