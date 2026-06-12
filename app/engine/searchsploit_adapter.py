"""
Adapter Pattern (spec section 18): the rest of the system talks to
`SearchsploitAdapter` rather than calling the `searchsploit` CLI directly,
so an alternative exploit data source (NVD, custom DB, …) can be swapped in
without touching `ExploitCorrelator`.

`SearchsploitTool` exposes the same install/version metadata as the scanner
classes so it can sit in `TOOL_REGISTRY` alongside them.
"""
import json
import shutil
import subprocess

from .scanner_base import ManagedTool


class SearchsploitTool(ManagedTool):
    name = "searchsploit"
    cli_name = "searchsploit"
    apt_package = "exploitdb"
    version_args = ["--version"]

    @classmethod
    def update_command(cls) -> str:
        # searchsploit's own updater does a git pull on /usr/share/exploitdb
        # which is root-owned, hence sudo.
        return "sudo searchsploit -u"


class SearchsploitAdapter:
    """
    Thin wrapper around `searchsploit --cve <id> -j`. Returns a list of
    exploit hit dicts as produced by Searchsploit's JSON mode, or `[]` if
    nothing was found or searchsploit isn't installed.
    """
    timeout_seconds = 30

    @staticmethod
    def is_available() -> bool:
        return shutil.which("searchsploit") is not None

    def lookup_cve(self, cve_id: str) -> list[dict]:
        if not self.is_available() or not cve_id:
            return []
        clean = cve_id.upper().replace("CVE-", "").strip()
        return self._run_search(["--cve", clean])

    def search_by_product(self, product: str, version: str | None = None) -> list[dict]:
        """Run a free-form `searchsploit <product> <version>` query.

        Used for the correlator's second pass — enriching scan results that
        carry a product/version banner but no specific CVE.
        """
        if not self.is_available() or not product:
            return []
        terms = [product]
        if version:
            terms.append(version)
        return self._run_search(terms)

    def _run_search(self, query_args: list[str]) -> list[dict]:
        argv = ["searchsploit", *query_args, "-j"]
        try:
            result = subprocess.run(
                argv, capture_output=True, text=True, timeout=self.timeout_seconds,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []
        if result.returncode != 0 and not result.stdout.strip():
            return []
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []
        return data.get("RESULTS_EXPLOIT", []) or []
