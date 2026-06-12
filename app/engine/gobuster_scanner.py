from .scanner_base import BaseScanner


class GobusterScanner(BaseScanner):
    name = "gobuster"
    cli_name = "gobuster"
    apt_package = "gobuster"
    version_args = ["version"]
    timeout_seconds = 600

    # `port` and `scheme` are populated by the orchestrator from prior Nmap
    # findings (FR-04: "auto-trigger directory brute-forcing on DETECTED
    # HTTP/HTTPS services"). Defaults preserve the previous behaviour when
    # the orchestrator can't infer a port.
    def __init__(self, target_ip, port: int = 80, scheme: str = "http"):
        super().__init__(target_ip)
        self.port = port
        self.scheme = scheme

    def _url(self) -> str:
        default_port = 443 if self.scheme == "https" else 80
        if self.port and self.port != default_port:
            return f"{self.scheme}://{self.target_ip}:{self.port}"
        return f"{self.scheme}://{self.target_ip}"

    def get_command(self):
        # -q: quiet (suppresses banner so the parser sees only result lines)
        # Wordlist hard-coded to Kali's dirb common.txt for now — FYP2 could
        # promote this to a per-scan setting.
        return [
            "gobuster", "dir",
            "-u", self._url(),
            "-w", "/usr/share/dirb/wordlists/common.txt",
            "-q",
        ]
