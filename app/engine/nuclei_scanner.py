from .scanner_base import BaseScanner


class NucleiScanner(BaseScanner):
    name = "nuclei"
    cli_name = "nuclei"
    apt_package = "nuclei"
    version_args = ["-version"]
    timeout_seconds = 900

    def get_command(self):
        # -jsonl: structured output, one finding per line
        # -silent: suppress progress banner so only JSONL hits stdout
        return ["nuclei", "-u", self.target_ip, "-jsonl", "-silent"]

    @classmethod
    def update_command(cls) -> str:
        # Two steps: apt-managed binary AND the templates. The template refresh
        # is the higher-impact step for catching new CVEs.
        return (
            f"sudo apt-get install -y --only-upgrade {cls.apt_package} "
            f"&& nuclei -update-templates"
        )
