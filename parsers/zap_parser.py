"""Parser for the ZAP REST API alerts JSON ({"alerts": [...]})."""

import json
from pathlib import Path
from typing import List

from models.finding import Finding
from utils.logger import get_logger


def parse(raw_path: Path) -> List[Finding]:
    """Parse zap_report.json into a list of Finding objects."""
    log = get_logger()
    if raw_path is None or not Path(raw_path).exists():
        return []
    try:
        data = json.loads(Path(raw_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log.warning("ZAP parser: citanje nije uspjelo: %s", exc)
        return []

    alerts = data.get("alerts", []) if isinstance(data, dict) else []
    findings: List[Finding] = []
    for a in alerts:
        param = a.get("param") or None
        dokaz = a.get("evidence") or a.get("attack") or ""
        findings.append(
            Finding(
                alat="OWASP ZAP",
                ranjivost=a.get("name") or a.get("alert") or "",
                url=a.get("url", ""),
                parametar=param,
                ozbiljnost=a.get("risk", ""),
                opis=a.get("description", ""),
                dokaz=dokaz,
            )
        )
    log.info("ZAP parser: %d nalaza", len(findings))
    return findings
