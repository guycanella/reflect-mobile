"""
Maestro runner for Reflect.

Handles GUI automation flows for mobile app testing.
"""

import subprocess
import time
import yaml
from typing import Optional
from dataclasses import dataclass
from pathlib import Path
from enum import Enum


class FlowResult(Enum):
    """Result of a Maestro flow execution."""
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass
class FlowExecutionResult:
    """Result of executing a Maestro flow."""
    result: FlowResult
    flow_name: str
    duration_seconds: float
    output: str
    error: Optional[str] = None
    screenshots: list[Path] = None
    
    def __post_init__(self):
        if self.screenshots is None:
            self.screenshots = []


class MaestroRunner:
    """
    Executes Maestro flows for GUI-based testing.
    
    Maestro is used to automate user interactions like:
    - Login flows
    - Navigation to protected resources
    - Logout flows
    - GUI state assertions
    """
    
    FLOWS_DIR = Path(__file__).parent.parent.parent.parent / "flows"
    
    def __init__(self, device_id: Optional[str] = None):
        """
        Initialize Maestro runner.
        
        Args:
            device_id: Target device ID (e.g., emulator-5554)
        """
        self.device_id = device_id
        self._ensure_flows_dir()
    
    def _ensure_flows_dir(self) -> None:
        """Create flows directory if it doesn't exist."""
        self.FLOWS_DIR.mkdir(parents=True, exist_ok=True)
    
    def set_device(self, device_id: str) -> None:
        """
        Set target device for flow execution.
        
        Args:
            device_id: Device ID from adb devices
        """
        self.device_id = device_id
    
    def run_flow(
        self, 
        flow_path: Path, 
        timeout: int = 120,
        env: Optional[dict] = None
    ) -> FlowExecutionResult:
        """
        Execute a Maestro flow file.
        
        Args:
            flow_path: Path to the .yaml flow file
            timeout: Maximum execution time in seconds
            env: Environment variables to pass to the flow
            
        Returns:
            FlowExecutionResult with status and details
        """
        if not flow_path.exists():
            return FlowExecutionResult(
                result=FlowResult.ERROR,
                flow_name=flow_path.name,
                duration_seconds=0,
                output="",
                error=f"Flow file not found: {flow_path}"
            )
        
        # Build command
        cmd = ["maestro", "test", str(flow_path)]
        
        if self.device_id:
            cmd.extend(["--device", self.device_id])
        
        # Add environment variables
        run_env = dict(subprocess.os.environ)
        if env:
            run_env.update({k: str(v) for k, v in env.items()})
        
        start_time = time.time()
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=run_env
            )
            
            duration = time.time() - start_time
            
            # Determine result based on return code
            if result.returncode == 0:
                flow_result = FlowResult.PASSED
            else:
                flow_result = FlowResult.FAILED
            
            return FlowExecutionResult(
                result=flow_result,
                flow_name=flow_path.name,
                duration_seconds=duration,
                output=result.stdout,
                error=result.stderr if result.returncode != 0 else None
            )
            
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return FlowExecutionResult(
                result=FlowResult.TIMEOUT,
                flow_name=flow_path.name,
                duration_seconds=duration,
                output="",
                error=f"Flow execution timed out after {timeout} seconds"
            )
        except FileNotFoundError:
            return FlowExecutionResult(
                result=FlowResult.ERROR,
                flow_name=flow_path.name,
                duration_seconds=0,
                output="",
                error="Maestro not found. Install from: https://maestro.mobile.dev"
            )
    
    def run_flow_string(
        self,
        flow_content: str,
        flow_name: str = "temp_flow",
        timeout: int = 120,
        env: Optional[dict] = None
    ) -> FlowExecutionResult:
        """
        Execute a flow from a YAML string.
        
        Args:
            flow_content: YAML content of the flow
            flow_name: Name for the temporary flow
            timeout: Maximum execution time
            env: Environment variables
            
        Returns:
            FlowExecutionResult with status and details
        """
        # Write to temporary file
        temp_path = self.FLOWS_DIR / f"{flow_name}.yaml"
        temp_path.write_text(flow_content)
        
        try:
            return self.run_flow(temp_path, timeout, env)
        finally:
            # Cleanup temp file
            if temp_path.exists():
                temp_path.unlink()
    
    def generate_login_flow(
        self,
        package_name: str,
        username_field_id: Optional[str] = None,
        password_field_id: Optional[str] = None,
        login_button_id: Optional[str] = None,
        username: str = "testuser@example.com",
        password: str = "testpassword123"
    ) -> str:
        """
        Generate a login flow YAML.
        
        Args:
            package_name: App package name
            username_field_id: ID of username input field
            password_field_id: ID of password input field
            login_button_id: ID of login button
            username: Test username
            password: Test password
            
        Returns:
            YAML string for the login flow
        """
        flow = {
            "appId": package_name,
            "name": "Login Flow",
            "tags": ["auth", "login"],
            "env": {
                "USERNAME": username,
                "PASSWORD": password
            },
            "---": None  # Separator
        }
        
        steps = [
            {"launchApp": {"appId": package_name, "clearState": True}}
        ]
        
        # Username input
        if username_field_id:
            steps.append({"tapOn": {"id": username_field_id}})
        else:
            steps.append({"tapOn": {"text": ".*email.*|.*username.*|.*user.*", "regex": True}})
        steps.append({"inputText": "${USERNAME}"})
        
        # Password input
        if password_field_id:
            steps.append({"tapOn": {"id": password_field_id}})
        else:
            steps.append({"tapOn": {"text": ".*password.*|.*senha.*", "regex": True}})
        steps.append({"inputText": "${PASSWORD}"})
        
        # Login button
        if login_button_id:
            steps.append({"tapOn": {"id": login_button_id}})
        else:
            steps.append({"tapOn": {"text": ".*login.*|.*sign.?in.*|.*entrar.*", "regex": True}})
        
        # Wait for result
        steps.append({"waitForAnimationToEnd": True})
        
        # Build YAML manually for proper formatting
        yaml_content = f"""appId: {package_name}
name: Login Flow
tags:
  - auth
  - login
env:
  USERNAME: "{username}"
  PASSWORD: "{password}"
---
"""
        for step in steps:
            yaml_content += f"- {yaml.dump(step, default_flow_style=True).strip()}\n"
        
        return yaml_content
    
    def generate_navigation_flow(
        self,
        package_name: str,
        target_screen_text: str,
        steps: Optional[list[dict]] = None
    ) -> str:
        """
        Generate a navigation flow to reach a specific screen.
        
        Args:
            package_name: App package name
            target_screen_text: Text that identifies the target screen
            steps: Optional list of navigation steps
            
        Returns:
            YAML string for the navigation flow
        """
        yaml_content = f"""appId: {package_name}
name: Navigate to Protected Resource
tags:
  - navigation
  - protected
---
"""
        if steps:
            for step in steps:
                yaml_content += f"- {yaml.dump(step, default_flow_style=True).strip()}\n"
        
        # Assert we reached the target
        yaml_content += f'- assertVisible: "{target_screen_text}"\n'
        
        return yaml_content
    
    def generate_logout_flow(
        self,
        package_name: str,
        logout_button_id: Optional[str] = None
    ) -> str:
        """
        Generate a logout flow.
        
        Args:
            package_name: App package name
            logout_button_id: ID of logout button
            
        Returns:
            YAML string for the logout flow
        """
        yaml_content = f"""appId: {package_name}
name: Logout Flow
tags:
  - auth
  - logout
---
"""
        # Try to find and tap logout
        if logout_button_id:
            yaml_content += f'- tapOn:\n    id: "{logout_button_id}"\n'
        else:
            # Try common patterns
            yaml_content += """- tapOn:
    text: ".*logout.*|.*log.?out.*|.*sign.?out.*|.*sair.*|.*exit.*"
    regex: true
    optional: true
"""
        
        yaml_content += "- waitForAnimationToEnd: true\n"
        
        return yaml_content
    
    def generate_gui_capture_flow(
        self,
        package_name: str,
        output_path: str = "/tmp/reflect_gui_state.png"
    ) -> str:
        """
        Generate a flow that captures the current GUI state.
        
        Args:
            package_name: App package name
            output_path: Where to save the screenshot
            
        Returns:
            YAML string for the capture flow
        """
        return f"""appId: {package_name}
name: Capture GUI State
tags:
  - capture
  - assertion
---
- takeScreenshot: {output_path}
"""
    
    def generate_assertion_flow(
        self,
        package_name: str,
        should_see: Optional[list[str]] = None,
        should_not_see: Optional[list[str]] = None
    ) -> str:
        """
        Generate a flow that asserts GUI state.
        
        Args:
            package_name: App package name
            should_see: List of texts that should be visible
            should_not_see: List of texts that should NOT be visible
            
        Returns:
            YAML string for the assertion flow
        """
        yaml_content = f"""appId: {package_name}
name: GUI Assertion
tags:
  - assertion
---
"""
        
        if should_see:
            for text in should_see:
                yaml_content += f'- assertVisible: "{text}"\n'
        
        if should_not_see:
            for text in should_not_see:
                yaml_content += f'- assertNotVisible: "{text}"\n'
        
        return yaml_content
    
    def save_flow(self, flow_content: str, name: str) -> Path:
        """
        Save a flow to the flows directory.
        
        Args:
            flow_content: YAML content
            name: Flow name (without .yaml extension)
            
        Returns:
            Path to the saved flow file
        """
        flow_path = self.FLOWS_DIR / f"{name}.yaml"
        flow_path.write_text(flow_content)
        return flow_path
    
    def list_flows(self) -> list[Path]:
        """
        List all available flow files.
        
        Returns:
            List of paths to flow files
        """
        return list(self.FLOWS_DIR.glob("*.yaml"))


def check_maestro_installed() -> bool:
    """
    Check if Maestro is installed and accessible.
    
    Returns:
        True if installed, False otherwise
    """
    try:
        result = subprocess.run(
            ["maestro", "--version"],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def get_maestro_version() -> Optional[str]:
    """
    Get installed Maestro version.
    
    Returns:
        Version string or None if not installed
    """
    try:
        result = subprocess.run(
            ["maestro", "--version"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except FileNotFoundError:
        pass
    return None