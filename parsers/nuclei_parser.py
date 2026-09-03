"""Parser for Nuclei JSONL output."""

import json
from pathlib import Path
from typing import List

from models.finding import Finding
from utils.logger import get_logger


def parse(raw_path: Path) -> List[Finding]:
    """Parse nuclei_report.jsonl into a list of Finding objects."""
    log = get_logger()
    if raw_path is None or not Path(raw_path).exists():
        return []

    findings: List[Finding] = []
    try:
        lines = Path(raw_path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        log.warning("Nuclei parser: citanje nije uspjelo: %s", exc)
        return []

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue

        info = obj.get("info", {}) or {}
        dokaz = obj.get("matcher-name") or obj.get("extracted-results") or obj.get("matched-at") or ""
        if isinstance(dokaz, list):
            dokaz = ", ".join(str(x) for x in dokaz)
        findings.append(
            Finding(
                alat="Nuclei",
                ranjivost=info.get("name") or obj.get("template-id") or "",
                url=obj.get("matched-at") or obj.get("host") or "",
                parametar=None,
                ozbiljnost=info.get("severity", ""),
                opis=info.get("description", "") or "",
                dokaz=str(dokaz),
            )
        )
    log.info("Nuclei parser: %d nalaza", len(findings))
    return findings
