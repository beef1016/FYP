import os

from .scanner_base import BaseScanner


# First existing wordlist wins. Portable across the minimal Docker image
# (the `dirb` apt package installs /usr/share/dirb/wordlists/) and a full Kali
# install (which also exposes /usr/share/wordlists/dirb/ via the `wordlists`
# metapackage). Hard-coding either one breaks the other environment.
_WORDLIST_CANDIDATES = [
    "/usr/share/dirb/wordlists/common.txt",   # dirb apt package (Docker image + Kali)
    "/usr/share/wordlists/dirb/common.txt",   # full Kali (wordlists symlink)
]


def _wordlist() -> str:
    for path in _WORDLIST_CANDIDATES:
        if os.path.isfile(path):
            return path
    return _WORDLIST_CANDIDATES[0]   # sensible fallback if neither is present


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
        # Wordlist is resolved at runtime (see _wordlist) so the same code works
        # on both the minimal Docker image and a full Kali install.
        return [
            "gobuster", "dir",
            "-u", self._url(),
            "-w", _wordlist(),
            "-q",
        ]
