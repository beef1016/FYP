from .scanner_base import BaseScanner


class WhatWebScanner(BaseScanner):
    name = "whatweb"
    cli_name = "whatweb"
    apt_package = "whatweb"

    # Mirrors GobusterScanner: the orchestrator passes the port + scheme that
    # Nmap (or the user's URL hint) said HTTP/HTTPS is on, so WhatWeb actually
    # fingerprints the right service. Defaults preserve plain-HTTP behaviour
    # for callers that don't know any better.
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
        # -a 1: Stealthy/fast aggression level
        # -q:   Quiet — suppresses non-JSON banner text
        # --log-json -: write the structured JSON log to stdout
        return ["whatweb", "-a", "1", "-q", "--log-json", "-", self._url()]
