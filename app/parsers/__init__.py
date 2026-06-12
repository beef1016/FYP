"""Tool-output parsers. Each parser writes Vulnerability rows for one target_id.

`PARSERS` is the dispatch map used by OrchestrationEngine — keyed by the same
tool `name` the SCANNER_REGISTRY uses.
"""
from .nmap_parser import parse_nmap_xml
from .whatweb_parser import parse_whatweb_json
from .nuclei_parser import parse_nuclei_json
from .gobuster_parser import parse_gobuster_text

PARSERS = {
    "nmap":     parse_nmap_xml,
    "whatweb":  parse_whatweb_json,
    "nuclei":   parse_nuclei_json,
    "gobuster": parse_gobuster_text,
}

__all__ = [
    "PARSERS",
    "parse_nmap_xml", "parse_whatweb_json",
    "parse_nuclei_json", "parse_gobuster_text",
]
