"""Nuclei wrapper - runs the nuclei CLI and captures JSONL output."""

import subprocess
from pathlib import Path
from typing import Any, Optional

from utils.logger import get_logger
from wrappers.base_wrapper import BaseWrapper


class NucleiWrapper(BaseWrapper):
    """Runs nuclei against the target and writes nuclei_report.jsonl."""

    naziv = "Nuclei"

    def __init__(self, config: dict):
        super().__init__(config)
        self.binary = self.config.get("binary", "nuclei")
        self.tags = self.config.get("tags", [])
        self.severity = self.config.get("severity", [])
        self.timeout = int(self.config.get("timeout_seconds", 600))

    def run(self, target: str, output_dir: Path, **kwargs: Any) -> Optional[Path]:
        """Run nuclei and return the path to the JSONL report."""
        log = get_logger()
        sid = kwargs.get("sid", "")
        out_file = output_dir / "nuclei_report.jsonl"

        cmd = [
            self.binary,
            "-u", target,
            "-jsonl",
            "-o", str(out_file),
        ]
        if self.tags:
            cmd += ["-tags", ",".join(self.tags)]
        if self.severity:
            cmd += ["-severity", ",".join(self.severity)]
        if sid:
            cmd += ["-H", f"Cookie: PHPSESSID={sid}; security=low"]
        cmd += ["-silent", "-no-color"]

        log.info("Nuclei: pokrecem sken (%s)", target)
        try:
            subprocess.run(cmd, timeout=self.timeout, capture_output=True, text=True)
        except FileNotFoundError:
            log.warning("Nuclei binary '%s' nije pronaden na PATH-u - preskacem", self.binary)
            return None
        except subprocess.TimeoutExpired:
            log.warning("Nuclei: istekao timeout (%ss), koristim dostupne nalaze", self.timeout)

        if out_file.exists():
            log.info("Nuclei: izvjestaj spremljen (%s)", out_file.name)
            return out_file
        log.info("Nuclei: nema nalaza")
        return out_file
