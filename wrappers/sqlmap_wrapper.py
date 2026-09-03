"""sqlmap wrapper - runs sqlmap per endpoint and captures its text output."""

import subprocess
from pathlib import Path
from typing import Any, List, Optional, Tuple

from utils.logger import get_logger
from wrappers.base_wrapper import BaseWrapper


class SqlmapWrapper(BaseWrapper):
    """Runs sqlmap for each configured endpoint and returns (url, raw_path) pairs."""

    naziv = "sqlmap"

    def __init__(self, config: dict):
        super().__init__(config)
        self.binary = self.config.get("binary", "sqlmap")
        self.endpoints = self.config.get("endpoints", [])
        self.technique = self.config.get("technique", "BEUST")
        self.level = self.config.get("level", 1)
        self.risk = self.config.get("risk", 1)
        self.timeout = int(self.config.get("timeout_seconds", 600))

    def run(self, target: str, output_dir: Path, **kwargs: Any) -> Optional[List[Tuple[str, Path]]]:
        """Run sqlmap for every endpoint; return list of (full_url, raw_txt_path)."""
        log = get_logger()
        sid = kwargs.get("sid", "")
        target = target.rstrip("/")
        results: List[Tuple[str, Path]] = []

        for i, endpoint in enumerate(self.endpoints):
            full_url = f"{target}{endpoint}"
            raw_path = output_dir / f"sqlmap_{i}.txt"
            cmd = [
                self.binary,
                "-u", full_url,
                "--batch",
                "--technique", self.technique,
                "--level", str(self.level),
                "--risk", str(self.risk),
                "--output-dir", str(output_dir / "sqlmap"),
            ]
            if sid:
                cmd += ["--cookie", f"PHPSESSID={sid}; security=low"]

            log.info("sqlmap: skeniram endpoint %s", endpoint)
            stdout, stderr = "", ""
            try:
                res = subprocess.run(cmd, timeout=self.timeout, capture_output=True, text=True)
                stdout, stderr = res.stdout, res.stderr
            except FileNotFoundError:
                log.warning("sqlmap binary '%s' nije pronaden na PATH-u - preskacem", self.binary)
                return results or None
            except subprocess.TimeoutExpired as exc:
                stdout = exc.stdout or ""
                stderr = exc.stderr or ""
                log.warning("sqlmap: istekao timeout na %s, koristim djelomicni izlaz", endpoint)

            try:
                raw_path.write_text((stdout or "") + "\n" + (stderr or ""), encoding="utf-8")
                results.append((full_url, raw_path))
            except OSError as exc:
                log.warning("sqlmap: zapis izlaza nije uspio: %s", exc)

        return results or None
