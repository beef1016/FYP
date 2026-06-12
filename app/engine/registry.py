"""Tool registries.

`SCANNER_REGISTRY` (ordered) drives the scan pipeline.
`TOOL_REGISTRY` is the superset used by the Tool Management UI; it adds
non-scanner tools like Searchsploit.
"""
from .nmap_scanner import NmapScanner
from .whatweb_scanner import WhatWebScanner
from .nuclei_scanner import NucleiScanner
from .gobuster_scanner import GobusterScanner
from .searchsploit_adapter import SearchsploitTool

# Order matters — this is also the default scan pipeline order.
SCANNER_REGISTRY = {
    cls.name: cls for cls in (NmapScanner, WhatWebScanner, NucleiScanner, GobusterScanner)
}

TOOL_REGISTRY = {
    **SCANNER_REGISTRY,
    SearchsploitTool.name: SearchsploitTool,
}
