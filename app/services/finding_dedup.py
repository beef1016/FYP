"""Cross-tool finding correlation — the *keep-both-and-link* strategy.

Different tools report overlapping things, but the overlaps are of two very
different KINDS, and conflating them is misleading:

1. **Same finding** (identity). Nuclei and ZAP both flag the same CVE; Nmap and
   WhatWeb both fingerprint the same server banner. These are the *same issue*
   seen twice — genuine corroboration ("also detected by …").

2. **Same location** (co-location). Gobuster discovers the path ``/admin`` and
   ZAP happens to raise a SQL-injection alert at ``/admin``. They are NOT the
   same finding — Gobuster only confirmed the path EXISTS, it did not detect the
   injection. Treating this as "also detected by" would wrongly credit Gobuster
   with ZAP's vulnerability (and, because a shared path bridges every alert on
   that path, would also merge ZAP's unrelated alerts with each other).

So the two kinds are clustered SEPARATELY, into independent groupings:

  * identity grouping  (``dup_group`` / ``dup_tools``)   — CVE + software banner
  * co-location group  (``loc_group`` / ``loc_tools``)    — URL path

A path match can therefore never pollute an identity cluster, and the UI frames
the two differently ("also detected by X" vs "same path also mapped by X").

Within each kind, rows sharing ANY signature are unioned (union-find), and a
cluster is kept only when it spans **two or more distinct tools**. Sameness is
decided by *anchor* signatures only — a shared CVE id, an exact product-token +
version, or an exact URL path — never fuzzy title similarity.

Determinism (NFR-03): group ids are assigned from a CONTENT-derived ordering
key (host, port, tool, finding), never from database row ids. Row ids are
unstable across repeat scans because the concurrent phase inserts findings in
completion order, so numbering by content keeps repeat scans identical. The
clustering is a pure function of the rows passed in (reads attributes, writes
nothing), so it unit-tests without a database.
"""
import re


# Product-name tokens too generic to anchor a match on their own. "Apache httpd"
# and "Apache Tomcat" must not merge just because both say "httpd"/"server".
_GENERIC_PRODUCT_TOKENS = {
    "httpd", "server", "web", "service", "services", "daemon",
    "http", "https", "ssl", "tls", "the",
}

_WORD_RE = re.compile(r"[a-z0-9]+")
_GOBUSTER_PATH_RE = re.compile(r"Hidden directory:\s*(/\S+)", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s\]\)]+", re.IGNORECASE)
_NUCLEI_MATCHED_RE = re.compile(r"\[matched:\s*(\S+?)\]", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# Field helpers (duck-typed: anything with the ScanResult attributes works,    #
# so tests can pass a SimpleNamespace instead of a DB row).                    #
# --------------------------------------------------------------------------- #
def _host(row):
    return (getattr(row, "host", "") or "").strip().lower()


def _port(row):
    return getattr(row, "port", None)


def _tool(row):
    return (getattr(row, "tool_name", "") or "").strip()


def _order_key(row):
    """Content-derived sort key — stable across repeat scans (NOT row id)."""
    port = _port(row)
    return (_host(row), port if port is not None else -1,
            _tool(row).lower(), (getattr(row, "finding", "") or ""))


def _product_tokens(product):
    """Specific, lower-cased word tokens from a product name (generics dropped)."""
    toks = _WORD_RE.findall((product or "").lower())
    return [t for t in toks if len(t) > 1 and t not in _GENERIC_PRODUCT_TOKENS]


def significant_product_tokens(product):
    """Public alias — the ONE place that decides how a product name is reduced
    to comparable tokens (dropping generics like 'httpd'). Used by both the
    de-dup signatures and the exploit-correlation query, so a product is
    normalised identically everywhere (Nmap 'Apache httpd' == WhatWeb 'Apache').
    """
    return _product_tokens(product)


def _norm_path(candidate):
    """Normalise a URL/path to a comparable key, or None if not path-like.

    Strips query/fragment and a trailing slash, lower-cases, and ignores the
    bare site root ("/") which is too generic to anchor a match on.
    """
    if not candidate:
        return None
    p = candidate.split("?", 1)[0].split("#", 1)[0].strip()
    if not p.startswith("/"):
        return None
    p = p.rstrip("/").lower()
    return p or None


def _path_candidate(row):
    """Pull a URL path out of a Gobuster or ZAP finding, tool-aware."""
    tool = _tool(row).lower()
    text = getattr(row, "finding", "") or ""
    if tool == "gobuster":
        m = _GOBUSTER_PATH_RE.search(text)
        return m.group(1) if m else None
    if tool == "zap":
        m = _URL_RE.search(text)
        if not m:
            return None
        after_scheme = m.group(0).split("//", 1)[-1]
        if "/" not in after_scheme:
            return None
        return "/" + after_scheme.split("/", 1)[1]
    if tool == "nuclei":
        # The parser records the matched URL as "[matched: <url>]".
        m = _NUCLEI_MATCHED_RE.search(text)
        if not m:
            return None
        after_scheme = m.group(1).split("//", 1)[-1]
        if "/" not in after_scheme:
            return None
        return "/" + after_scheme.split("/", 1)[1]
    return None


# --------------------------------------------------------------------------- #
# Signature families                                                           #
# --------------------------------------------------------------------------- #
def _identity_signatures(row):
    """Anchors that mean 'the SAME underlying issue' — safe to merge/corroborate.

      * CVE: same CVE on the same host.
      * Service: same product on the same host:PORT. Version is deliberately
        NOT part of the key — one service occupies a host:port, so Nmap's
        'Apache httpd 2.2.8', WhatWeb's 'Apache 2.2.8' and Nuclei's
        'openssh-detect' all describe that one service even when their version
        strings differ in format. Port is required so two ports never merge.
    """
    sigs = []

    cve = (getattr(row, "cve_id", "") or "").strip().upper()
    if cve:
        sigs.append(("cve", _host(row), cve))

    product = getattr(row, "product", None)
    port = _port(row)
    if product and port is not None:
        for token in _product_tokens(product):
            sigs.append(("svc", _host(row), port, token))

    return sigs


def _location_signatures(row):
    """Anchors that mean 'the SAME location' — a URL path on a host:port.

    This is co-location, NOT identity: a shared path says two tools looked at
    the same resource, not that they found the same issue. Port is part of the
    key, so the same path on different ports stays separate.
    """
    path = _norm_path(_path_candidate(row))
    if path:
        return [("path", _host(row), _port(row), path)]
    return []


# --------------------------------------------------------------------------- #
# Clustering                                                                   #
# --------------------------------------------------------------------------- #
class _UnionFind:
    def __init__(self):
        self._parent = {}

    def add(self, x):
        self._parent.setdefault(x, x)

    def find(self, x):
        self._parent.setdefault(x, x)
        root = x
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[x] != root:   # path compression
            self._parent[x], x = root, self._parent[x]
        return root

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._parent[rb] = ra


def _cluster_by(rows, signature_fn):
    """Union rows sharing a signature; keep clusters spanning >= 2 distinct
    tools. Returns ``{row.id: (group_id, [sorted distinct tools])}``.

    Group ids are 1..N, assigned by the cluster's smallest CONTENT key (not row
    id), so repeat scans of the same findings number clusters identically
    regardless of the order rows were inserted.
    """
    uf = _UnionFind()
    sig_to_rows = {}
    for row in rows:
        rid = getattr(row, "id", None)
        if rid is None:
            continue
        uf.add(rid)
        for sig in signature_fn(row):
            sig_to_rows.setdefault(sig, []).append(rid)

    for rids in sig_to_rows.values():
        anchor = rids[0]
        for other in rids[1:]:
            uf.union(anchor, other)

    members = {}         # root -> list[row]
    for row in rows:
        rid = getattr(row, "id", None)
        if rid is None:
            continue
        members.setdefault(uf.find(rid), []).append(row)

    kept = []
    for cluster in members.values():
        tools = sorted({_tool(r) for r in cluster if _tool(r)})
        if len(cluster) < 2 or len(tools) < 2:
            continue
        order = min(_order_key(r) for r in cluster)
        kept.append((order, cluster, tools))
    kept.sort(key=lambda t: t[0])

    assignments = {}
    for group_id, (_order, cluster, tools) in enumerate(kept, start=1):
        for row in cluster:
            assignments[row.id] = (group_id, tools)
    return assignments


def cluster_findings(rows):
    """Correlate a scan's findings into identity and co-location groupings.

    Returns ``{row.id: info}`` for every row that belongs to at least one
    grouping, where ``info`` is a dict with keys:

        dup_group, dup_tools  — identity cluster (same finding), or None
        loc_group, loc_tools  — co-location cluster (same path), or None

    Rows in neither grouping are omitted (callers treat a missing id as "not
    correlated"). The two groupings are independent, so a path match can never
    put "also detected by" on a vulnerability a tool did not actually find.
    """
    identity = _cluster_by(rows, _identity_signatures)
    location = _cluster_by(rows, _location_signatures)

    out = {}
    for rid, (gid, tools) in identity.items():
        out.setdefault(rid, _blank())
        out[rid]["dup_group"] = gid
        out[rid]["dup_tools"] = tools
    for rid, (gid, tools) in location.items():
        out.setdefault(rid, _blank())
        out[rid]["loc_group"] = gid
        out[rid]["loc_tools"] = tools
    return out


def _blank():
    return {"dup_group": None, "dup_tools": None,
            "loc_group": None, "loc_tools": None}


# --------------------------------------------------------------------------- #
# Reporting helpers (pure; operate on already-clustered rows)                  #
# --------------------------------------------------------------------------- #
def finding_totals(rows):
    """Three honest counts for a scan's findings:

        reported  — raw hits the tools emitted. Parsers that collapse repeated
                    hits of one template (Nuclei) record how many via
                    `instance_count`, so this re-expands them; every other row
                    counts as 1.
        collapsed — rows after that intra-tool collapse (len(rows)); the figure
                    the dashboard/table actually lists.
        unique    — after ALSO merging cross-tool identity duplicates (the same
                    finding seen by several tools counts once). Co-located rows
                    (shared path, different issues) stay separate.

    Reported >= collapsed >= unique. Keeping all three avoids mixing a
    tool-reported total (e.g. an older poster's "115") with a post-collapse one.
    """
    collapsed = len(rows)
    reported = sum(int(getattr(r, "instance_count", 1) or 1) for r in rows)
    sizes = {}
    for r in rows:
        g = getattr(r, "dup_group", None)
        if g:
            sizes[g] = sizes.get(g, 0) + 1
    unique = collapsed - sum(k - 1 for k in sizes.values())
    return reported, collapsed, unique


def group_version_conflicts(rows):
    """Identity clusters whose members disagree on the software version.

    The identity signature is deliberately version-agnostic (one service owns a
    host:port, and tools format versions differently), so two tools reporting
    *different* versions of the same product still merge. That can hide a real
    disagreement, so this returns ``{dup_group: [distinct 'product version', …]}``
    for every cluster with more than one distinct banner — the UI surfaces both
    instead of silently picking one.
    """
    groups = {}
    for r in rows:
        g = getattr(r, "dup_group", None)
        product = getattr(r, "product", None)
        version = getattr(r, "version", None)
        if g and product and version:
            groups.setdefault(g, set()).add(f"{product} {version}".strip())
    return {g: sorted(v) for g, v in groups.items() if len(v) > 1}
