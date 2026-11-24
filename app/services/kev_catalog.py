"""CISA KEV (Known Exploited Vulnerabilities) catalog — offline enrichment.

Mirrors the Adapter Pattern used by `SearchsploitAdapter` (spec section 18):
`ExploitCorrelator` talks to `KevCatalog`, not to CISA directly, so the data
source can be swapped without touching the correlator.

OFFLINE-FIRST (matches the project's SME / air-gapped posture):
- The catalog is a single JSON file mirrored locally — NO network call happens
  during a scan. The file is refreshed out-of-band by `scripts/update_kev.sh`
  (or the UI's suggested command), exactly like `searchsploit -u`.
- Scanning never requires the file to exist; a missing/stale catalog simply
  means no KEV enrichment (the correlator degrades gracefully).

KEV answers a different question than Searchsploit: Searchsploit says "is there
a public PoC?", KEV says "is this CVE being exploited in the wild RIGHT NOW?".
A High/Critical with no indexed PoC but a KEV listing is still an urgent,
demonstrably-exploited finding — this is what compensates for the gaps the
supervisor asked about.
"""
import json
import os
from datetime import datetime, timezone

# Default location of the local mirror. Overridable via EXPLOITLINK_KEV_PATH so
# an operator can point at a shared/managed copy. `app/data/kev/` is created by
# the updater script; the file is intentionally NOT committed (it's refreshed
# data, not source — see scripts/update_kev.sh).
_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../app
DEFAULT_KEV_PATH = os.path.join(
    _APP_DIR, "data", "kev", "known_exploited_vulnerabilities.json"
)

# Official feed — used only by the updater script / the UI's suggested command,
# never fetched by the running app.
KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def _resolve_path(path: str | None = None) -> str:
    return path or os.environ.get("EXPLOITLINK_KEV_PATH") or DEFAULT_KEV_PATH


class KevCatalog:
    """Lazy, mtime-cached lookup over the local KEV JSON mirror.

    The file is (re)parsed only on first use and whenever its mtime changes, so
    a mid-session `update_kev.sh` is picked up without a restart.
    """

    def __init__(self, path: str | None = None):
        self.path = _resolve_path(path)
        self._index: dict[str, dict] | None = None
        self._mtime: float | None = None
        self._meta: dict = {}

    # --- loading ---------------------------------------------------------
    def _ensure_loaded(self) -> bool:
        """Return True if a parsed catalog is available (loading/reloading as
        needed). False if the file is absent or unreadable."""
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            self._index, self._mtime, self._meta = None, None, {}
            return False

        if self._index is not None and mtime == self._mtime:
            return True

        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            print(f"[KEV] Could not read catalog at {self.path}: {e}")
            self._index, self._mtime, self._meta = None, None, {}
            return False

        index: dict[str, dict] = {}
        for vuln in data.get("vulnerabilities", []) or []:
            cve = (vuln.get("cveID") or "").strip().upper()
            if cve:
                index[cve] = vuln
        self._index = index
        self._mtime = mtime
        self._meta = {
            "catalog_version": data.get("catalogVersion"),
            "date_released": data.get("dateReleased"),
            "count": data.get("count") or len(index),
        }
        print(f"[KEV] Loaded {len(index)} known-exploited CVEs "
              f"(catalog {self._meta.get('catalog_version')}).")
        return True

    # --- public API ------------------------------------------------------
    def is_available(self) -> bool:
        return self._ensure_loaded()

    def lookup(self, cve_id: str) -> dict | None:
        """Return a trimmed KEV record for a CVE, or None if not KEV-listed.

        The returned dict keeps only the fields the UI / report render, to keep
        the persisted `scan_results.kev_data` JSON small.
        """
        if not cve_id or not self._ensure_loaded():
            return None
        vuln = self._index.get(cve_id.strip().upper())
        if not vuln:
            return None
        return {
            "dateAdded": vuln.get("dateAdded"),
            "dueDate": vuln.get("dueDate"),
            "vulnerabilityName": vuln.get("vulnerabilityName"),
            "requiredAction": vuln.get("requiredAction"),
            "knownRansomwareCampaignUse": vuln.get("knownRansomwareCampaignUse"),
            "vendorProject": vuln.get("vendorProject"),
            "product": vuln.get("product"),
        }

    # --- freshness / provenance (staleness transparency) ----------------
    def catalog_version(self):
        self._ensure_loaded()
        return self._meta.get("catalog_version")

    def date_released(self):
        self._ensure_loaded()
        return self._meta.get("date_released")

    def count(self):
        self._ensure_loaded()
        return self._meta.get("count")

    def age_days(self) -> int | None:
        """Days since the local mirror file was last written. None if absent."""
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            return None
        delta = datetime.now(timezone.utc) - datetime.fromtimestamp(
            mtime, tz=timezone.utc
        )
        return delta.days

    def freshness_label(self) -> str:
        """Human one-liner for reports/UI, e.g.
        'CISA KEV catalog 2026.11.20 — 1,350 CVEs, mirror 2 day(s) old'."""
        if not self.is_available():
            return "CISA KEV catalog not installed (run scripts/update_kev.sh)"
        ver = self.catalog_version() or "unknown"
        cnt = self.count() or 0
        age = self.age_days()
        age_txt = f"mirror {age} day(s) old" if age is not None else "mirror age unknown"
        return f"CISA KEV catalog {ver} — {cnt:,} CVEs, {age_txt}"


class KevCatalogTool:
    """Tool-Management-UI metadata for the KEV mirror (mirrors SearchsploitTool).

    Not a scanner and has no CLI — it's a data feed — so it exposes the
    'how to refresh me' command instead of an apt install. The running app
    never executes this; the operator copies it to their terminal.
    """
    name = "cisa-kev"
    cli_name = ""
    apt_package = ""

    @classmethod
    def _catalog(cls) -> KevCatalog:
        return KevCatalog()

    @classmethod
    def is_installed(cls) -> bool:
        return cls._catalog().is_available()

    @classmethod
    def installed_version(cls):
        cat = cls._catalog()
        if not cat.is_available():
            return None
        return cat.freshness_label()

    @classmethod
    def install_command(cls) -> str:
        return "bash scripts/update_kev.sh"

    @classmethod
    def update_command(cls) -> str:
        return "bash scripts/update_kev.sh   # re-downloads the latest CISA KEV feed"
