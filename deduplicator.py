"""Deduplicator - dedup and correlation algorithm from chapter 4.5."""

from typing import List
from urllib.parse import urlsplit, urlunsplit

from models.finding import Finding
from utils.logger import get_logger

# ozbiljnost order za max operaciju (4.5)
OZBILJNOST_ORDER = {
    "informativno": 0,
    "nisko": 1,
    "srednje": 2,
    "visoko": 3,
    "kritično": 4,
}


def normalize_url(url: str) -> str:
    """Normalize a URL: lowercase scheme+host, drop query, strip trailing slashes."""
    if not url:
        return ""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()
    path = parts.path.rstrip("/")
    return urlunsplit((scheme, netloc, path, "", ""))


class Deduplicator:
    """Merges identical findings and correlates confirmations from multiple tools."""

    def _max_ozbiljnost(self, a: str, b: str) -> str:
        """Return the higher of two severity values using the fixed order."""
        return a if OZBILJNOST_ORDER.get(a, 0) >= OZBILJNOST_ORDER.get(b, 0) else b

    def deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """Apply the dedup/correlation algorithm and return the unique findings."""
        J: dict = {}
        for n in findings:
            kljuc = (normalize_url(n.url), n.parametar, n.ranjivost)
            if kljuc not in J:
                n.alati = [n.alat]
                n.dokazi = [n.dokaz] if n.dokaz else []
                J[kljuc] = n
            else:
                m = J[kljuc]
                if n.alat not in m.alati:
                    m.alati.append(n.alat)
                m.ozbiljnost = self._max_ozbiljnost(m.ozbiljnost, n.ozbiljnost)
                if n.dokaz and n.dokaz not in m.dokazi:
                    m.dokazi.append(n.dokaz)

        for m in J.values():
            m.korelirano = len(m.alati) >= 2

        rezultat = list(J.values())
        korelirano = sum(1 for f in rezultat if f.korelirano)
        log = get_logger()
        log.info("Deduplikacija: %d -> %d nalaza", len(findings), len(rezultat))
        log.info("Korelacija: %d koreliranih nalaza", korelirano)
        return rezultat
