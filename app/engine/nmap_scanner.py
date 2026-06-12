from .scanner_base import BaseScanner


class NmapScanner(BaseScanner):
    name = "nmap"
    cli_name = "nmap"
    apt_package = "nmap"
    timeout_seconds = 600  # -sV is materially slower than a bare -F scan

    def get_command(self):
        # -F: top 100 ports.  -sV: probe service/version banners on each open port.
        # -oX -: stream XML to stdout for the parser.
        return ["nmap", "-F", "-sV", "-oX", "-", self.target_ip]
