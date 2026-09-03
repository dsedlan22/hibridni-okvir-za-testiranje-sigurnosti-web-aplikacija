"""JSON reporter - writes the unified report as JSON."""

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import List

from models.finding import Finding
from utils.logger import get_logger


class JSONReporter:
    """Serializes findings and metadata into a single JSON report."""

    def generate(
        self,
        findings: List[Finding],
        output_dir: Path,
        target: str,
        tools_used: List[str],
        total_raw: int,
        execution_time: float,
    ) -> Path:
        """Write izvjestaj.json and return its path."""
        korelirano = sum(1 for f in findings if f.korelirano)
        payload = {
            "metadata": {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "target": target,
                "tools_used": tools_used,
                "total_findings_raw": total_raw,
                "total_findings_dedup": len(findings),
                "correlated_count": korelirano,
                "execution_time_seconds": round(execution_time, 1),
            },
            "findings": [asdict(f) for f in findings],
        }
        out = output_dir / "izvjestaj.json"
        out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        get_logger().info("JSON izvjestaj spremljen: %s", out)
        return out
