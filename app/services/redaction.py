"""Credential masking for shareable output.

Some findings legitimately capture the secret they tested — notably Nuclei's
`*-weak-credentials` / `*-default-login` templates, whose extracted results are
the guessed ``user:password`` pairs. That detail is useful locally in a lab, but
a PDF/JSON report is shareable, so the password half is masked before it leaves
the application. Masking is applied at render time (the raw finding stays in the
database for local analysis), via `ScanResult.finding_redacted`.
"""
import re

# A credential pair inside a finding's "found: …" segment, e.g. "admin:admin",
# "postgres:postgres". We mask only the secret half and only inside that
# segment, so version extracts ("found: 5.2.4") and matched URLs
# ("[matched: http://host/x]", which contain "://") are never touched.
_FOUND_SEGMENT_RE = re.compile(r"found:\s*[^\]|]+", re.IGNORECASE)
_CRED_PAIR_RE = re.compile(r"(\S+?):(\S+)")


def _mask_segment(match: "re.Match") -> str:
    segment = match.group(0)
    return _CRED_PAIR_RE.sub(lambda m: f"{m.group(1)}:****", segment)


def mask_credentials(text):
    """Return `text` with any ``name:secret`` pairs in a 'found: …' segment
    masked to ``name:****``. Non-credential text is returned unchanged."""
    if not text:
        return text
    return _FOUND_SEGMENT_RE.sub(_mask_segment, str(text))
