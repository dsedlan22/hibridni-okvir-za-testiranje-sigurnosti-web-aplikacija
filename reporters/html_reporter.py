"""HTML reporter - renders the unified report via a Jinja2 template."""

from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import List

from jinja2 import Environment, FileSystemLoader, select_autoescape

from models.finding import Finding
from utils.logger import get_logger

OZBILJNOST_ORDER = {
    "kritično": 0,
    "visoko": 1,
    "srednje": 2,
    "nisko": 3,
    "informativno": 4,
}

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"


class HTMLReporter:
    """Produces a self-contained HTML report."""

    def generate(
        self,
        findings: List[Finding],
        output_dir: Path,
        target: str,
        tools_used: List[str],
        total_raw: int,
        execution_time: float,
    ) -> Path:
        """Write izvjestaj.html and return its path."""
        env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=select_autoescape(["html"]),
        )
        template = env.get_template("report.html")

        sorted_findings = sorted(
            findings, key=lambda f: OZBILJNOST_ORDER.get(f.ozbiljnost, 99)
        )

        po_alatu: Counter = Counter()
        for f in findings:
            for a in (f.alati or [f.alat]):
                po_alatu[a] += 1

        owasp_pokrivenost: Counter = Counter(f.owasp_kategorija for f in findings)
        korelirano = sum(1 for f in findings if f.korelirano)

        html = template.render(
            timestamp=datetime.now().isoformat(timespec="seconds"),
            target=target,
            tools_used=tools_used,
            total_raw=total_raw,
            total_dedup=len(findings),
            korelirano=korelirano,
            execution_time=round(execution_time, 1),
            findings=sorted_findings,
            po_alatu=dict(po_alatu),
            owasp_pokrivenost=dict(owasp_pokrivenost),
        )
        out = output_dir / "izvjestaj.html"
        out.write_text(html, encoding="utf-8")
        get_logger().info("HTML izvjestaj spremljen: %s", out)
        return out
