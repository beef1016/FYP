import json
import re

from app.extensions import db
from app.models import ScanResult


_IGNORED_PLUGINS = {"Country", "IP", "HTTPServer"}

# Real software versions start with a digit cluster. WhatWeb's `Title` plugin
# emits the page title in its `version` slot, so we use this to filter it out
# of product/version enrichment without dropping the finding row itself.
_VERSION_LIKE = re.compile(r"^\d+(\.\d+)+")


def parse_whatweb_json(json_data: str, scan_id: str, target: str,
                       port: int | None = None, scheme: str = "http"):
    """Parser dispatch — `port`/`scheme` come from the orchestrator so each
    WhatWeb row records which HTTP service was fingerprinted."""
    if not json_data or "error" in json_data:
        return

    try:
        # WhatWeb sometimes emits a trailing comma before the closing bracket.
        cleaned_data = re.sub(r",(\s*])", r"\1", json_data.strip())
        results = json.loads(cleaned_data)

        for result in results:
            plugins = result.get("plugins", {}) or {}
            for plugin_name, plugin_data in plugins.items():
                if plugin_name in _IGNORED_PLUGINS:
                    continue

                versions = plugin_data.get("version", []) or []
                strings  = plugin_data.get("string", [])  or []

                detail_bits = []
                if versions:
                    detail_bits.append(f"Version: {', '.join(versions)}")
                if strings:
                    detail_bits.append(f"Details: {', '.join(strings)}")

                finding_text = f"Tech detected: {plugin_name}"
                if detail_bits:
                    finding_text += f" ({' | '.join(detail_bits)})"

                # Pick the first version-shaped string we see so the correlator
                # can search Exploit-DB by `<plugin_name> <version>`.
                clean_version = next(
                    (v for v in versions if v and _VERSION_LIKE.match(str(v))),
                    None,
                )

                db.session.add(ScanResult(
                    scan_id=scan_id,
                    tool_name="WhatWeb",
                    host=target,
                    port=port,
                    service=scheme,
                    finding=finding_text,
                    severity="Info",
                    raw_output=json.dumps({plugin_name: plugin_data}),
                    product=plugin_name if clean_version else None,
                    version=clean_version,
                ))

        db.session.commit()
        print("[PARSER] WhatWeb JSON parsing complete.")

    except Exception as e:
        db.session.rollback()
        print(f"[PARSER WARNING] Could not parse WhatWeb output: {e}")
