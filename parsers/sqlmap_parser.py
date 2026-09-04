"""Parser for sqlmap text output."""

import re
from pathlib import Path
from typing import List

from models.finding import Finding
from utils.logger import get_logger

PARAM_RE = re.compile(r"Parameter:\s*(?P<name>[^\s(]+)\s*\((?P<place>[^)]+)\)")
TYPE_RE = re.compile(r"^\s*Type:\s*(?P<type>.+?)\s*$", re.MULTILINE)
PAYLOAD_RE = re.compile(r"^\s*Payload:\s*(?P<payload>.+?)\s*$", re.MULTILINE)


def parse(raw_path: Path, target_url: str) -> List[Finding]:
    """Parse a sqlmap text report into Finding objects (one per injectable parameter)."""
    log = get_logger()
    if raw_path is None or not Path(raw_path).exists():
        return []
    try:
        text = Path(raw_path).read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        log.warning("sqlmap parser: citanje nije uspjelo: %s", exc)
        return []

    findings: List[Finding] = []
    matches = list(PARAM_RE.finditer(text))
    for idx, m in enumerate(matches):
        start = m.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        block = text[start:end]

        tipovi = [t.group("type").strip() for t in TYPE_RE.finditer(block)]
        payloadi = [p.group("payload").strip() for p in PAYLOAD_RE.finditer(block)]

        findings.append(
            Finding(
                alat="sqlmap",
                ranjivost="SQL Injection",
                url=target_url,
                parametar=m.group("name").strip(),
                ozbiljnost="visoko",
                opis="; ".join(tipovi),
                dokaz="; ".join(payloadi),
            )
        )
    log.info("sqlmap parser: %d nalaza (%s)", len(findings), Path(raw_path).name)
    return findings
