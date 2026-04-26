#!/usr/bin/env python3
"""
SCC CVE buckets — passive version-range → CVE list.

Pure lookup table.  No probes, no payloads.  An SCC fingerprint that
yielded a parseable version is matched against this table; matched CVEs
become *suspected* until an active confirmation step runs (Week 4+).

Confirmed CVEs only — speculative attributions in research dossier 03 are
deliberately omitted (see plan §H).  Re-add entries here only when an NVD
record explicitly names "SAP Cloud Connector" as the affected product.
"""
from __future__ import annotations

import re
from typing import Iterable


# (min_version_inclusive, max_version_exclusive, cve_id, severity, headline)
# A None bound means open-ended.
_BUCKETS: list[tuple] = [
    # SAP Note 3417627 — TLS cert validation flaw, fixed in 2.16.2.
    # Anything ≥ 2.0.0 and < 2.16.2 is in the affected window per the SAP
    # security patchday note.  Lower bound chosen conservatively at 2.0.0.
    ("2.0.0", "2.16.2", "CVE-2024-25642", "HIGH",
     "TLS cert validation flaw — patched in SCC 2.16.2"),
]


def _parse(v: str) -> tuple[int, ...]:
    """Parse an SCC version string ("2.16.0", "2.16.0.1") to a tuple."""
    if not v:
        return ()
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) if parts else ()


def _ge(a: tuple, b: tuple) -> bool:
    return a >= b


def _lt(a: tuple, b: tuple) -> bool:
    return a < b


def cves_for_version(version: str) -> list[dict]:
    """Return suspected CVEs for the given SCC version string.

    Each entry is a dict {cve, severity, headline, ref}.  Empty list when
    the version is unknown or no rule matches — callers should treat that
    as "version too new to flag" rather than "safe".
    """
    v = _parse(version)
    if not v:
        return []
    out = []
    for low, high, cve, sev, headline in _BUCKETS:
        lo = _parse(low) if low else (0,)
        hi = _parse(high) if high else (9999,)
        if _ge(v, lo) and _lt(v, hi):
            out.append({
                "cve": cve,
                "severity": sev,
                "headline": headline,
                "ref": f"https://nvd.nist.gov/vuln/detail/{cve}",
            })
    return out


def all_known_cves() -> Iterable[str]:
    return [b[2] for b in _BUCKETS]
