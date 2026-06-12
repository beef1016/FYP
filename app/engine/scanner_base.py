"""
Abstract scanner / managed-tool base classes.

Spec section 18 calls for an abstract `Scanner` with `run()` and `parseOutput()`.
We split that into two layers:

- `ManagedTool` — anything we want to check / install / update on the system,
  including tools that aren't scanners (e.g. Searchsploit).
- `BaseScanner` — extends ManagedTool with `execute_scan()`, the "run()" half.
  The "parseOutput()" half lives in `app/parsers/` and is dispatched by
  `OrchestrationEngine`, keeping I/O and parsing separable.
"""
import subprocess
import shutil
from abc import ABC, abstractmethod


class ManagedTool:
    """
    Tool metadata + presence/version detection + suggested install/update
    commands. The Flask process never executes the install/update commands
    itself — see CLAUDE.md for the rationale.
    """
    name: str = ""
    cli_name: str = ""
    apt_package: str = ""
    version_args = ["--version"]

    @classmethod
    def is_installed(cls) -> bool:
        return shutil.which(cls.cli_name) is not None

    @classmethod
    def installed_version(cls):
        if not cls.is_installed():
            return None
        try:
            result = subprocess.run(
                [cls.cli_name, *cls.version_args],
                capture_output=True, text=True, timeout=15,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        blob = (result.stdout or "") + (result.stderr or "")
        first = next((ln.strip() for ln in blob.splitlines() if ln.strip()), "")
        return first or None

    @classmethod
    def install_command(cls) -> str:
        return f"sudo apt-get install -y {cls.apt_package}"

    @classmethod
    def update_command(cls) -> str:
        return f"sudo apt-get install -y --only-upgrade {cls.apt_package}"


class BaseScanner(ManagedTool, ABC):
    """Concrete scanners subclass this and implement `get_command()`."""
    timeout_seconds = 300

    def __init__(self, target_ip):
        self.target_ip = target_ip

    @abstractmethod
    def get_command(self):
        """Return the argv list to run. Never a shell string."""

    def execute_scan(self):
        command = self.get_command()
        print(f"[SYSTEM] Executing: {' '.join(command)}")
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "error_message": f"{command[0]} exceeded {self.timeout_seconds}s timeout",
            }
        except FileNotFoundError:
            return {
                "status": "error",
                "error_message": f"Tool not installed on this system: {command[0]}",
            }

        # Nuclei / Gobuster can return non-zero even with usable findings.
        if result.stdout and result.stdout.strip():
            return {"status": "success", "output": result.stdout}
        if result.returncode == 0:
            return {"status": "success", "output": ""}
        return {
            "status": "error",
            "error_message": (result.stderr or "").strip()
                             or f"{command[0]} exited with code {result.returncode}",
        }
