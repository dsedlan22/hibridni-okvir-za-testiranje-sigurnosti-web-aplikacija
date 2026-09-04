"""OWASP ZAP wrapper - drives an already running ZAP daemon over its REST API."""

import json
import time
from pathlib import Path
from typing import Any, Optional

import requests

from utils.logger import get_logger
from wrappers.base_wrapper import BaseWrapper

POLL_INTERVAL = 3


class ZapWrapper(BaseWrapper):
    """Spider + active scan through the ZAP REST API (no Docker, no zap library)."""

    naziv = "OWASP ZAP"

    def __init__(self, config: dict):
        super().__init__(config)
        self.api_url = self.config.get("api_url", "http://127.0.0.1:8090").rstrip("/")
        self.api_key = self.config.get("api_key", "")
        self.timeout = int(self.config.get("timeout_seconds", 900))

    def _get(self, path: str, params: Optional[dict] = None) -> Optional[dict]:
        """Perform a single ZAP REST API GET call."""
        params = dict(params or {})
        if self.api_key:
            params["apikey"] = self.api_key
        try:
            resp = requests.get(f"{self.api_url}{path}", params=params, timeout=60)
            resp.raise_for_status()
            return resp.json()
        except (requests.RequestException, ValueError) as exc:
            get_logger().warning("ZAP API poziv %s nije uspio: %s", path, exc)
            return None

    def _wait_for_scan(self, path: str, scan_id: str, faza: str) -> None:
        """Poll a ZAP scan status endpoint until it reaches 100% or the timeout expires."""
        log = get_logger()
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            data = self._get(path, {"scanId": scan_id})
            if data is None:
                return
            status = data.get("status", "0")
            log.info("ZAP %s napredak: %s%%", faza, status)
            if str(status) == "100":
                return
            time.sleep(POLL_INTERVAL)
        log.warning("ZAP %s: istekao timeout (%ss), nastavljam s dostupnim nalazima", faza, self.timeout)

    def run(self, target: str, output_dir: Path, **kwargs: Any) -> Optional[Path]:
        """Run ZAP against the target and store the alerts in zap_report.json."""
        log = get_logger()
        sid = kwargs.get("sid", "")

        version = self._get("/JSON/core/view/version/")
        if version is None:
            log.warning("ZAP daemon nije dostupan na %s - preskacem alat", self.api_url)
            return None
        log.info("ZAP daemon dostupan, verzija %s", version.get("version", "?"))

        self._get("/JSON/core/action/newSession/", {"name": "okvir", "overwrite": "true"})

        if sid:
            self._get("/JSON/replacer/action/removeRule/", {"description": "dvwa"})
            res = self._get(
                "/JSON/replacer/action/addRule/",
                {
                    "description": "dvwa",
                    "enabled": "true",
                    "matchType": "REQ_HEADER",
                    "matchRegex": "false",
                    "matchString": "Cookie",
                    "replacement": f"PHPSESSID={sid}; security=low",
                },
            )
            if res is not None:
                log.info("ZAP: replacer pravilo s DVWA kolacicem postavljeno")
            else:
                log.warning("ZAP: replacer pravilo nije postavljeno - sken moze biti neautenticiran")

        log.info("ZAP: ubacujem metu u stablo (%s)", target)
        self._get("/JSON/core/action/accessUrl/", {"url": target, "followRedirects": "true"})

        for rx in (r".*logout\.php.*", r".*/vulnerabilities/csrf.*"):
            self._get("/JSON/spider/action/excludeFromScan/", {"regex": rx})

        if self.config.get("spider", True):
            log.info("ZAP: pokrecem spider")
            data = self._get("/JSON/spider/action/scan/", {"url": target, "recurse": "true"})
            if data and data.get("scan"):
                self._wait_for_scan("/JSON/spider/view/status/", data["scan"], "spider")

        if self.config.get("active_scan", True):
            log.info("ZAP: pokrecem aktivni sken")
            data = self._get(
                "/JSON/ascan/action/scan/",
                {"url": target, "recurse": "true", "inScopeOnly": "false"},
            )
            if data and data.get("scan"):
                self._wait_for_scan("/JSON/ascan/view/status/", data["scan"], "aktivni sken")

        alerts_data = self._get(
            "/JSON/core/view/alerts/", {"baseurl": target, "start": "0", "count": "9999"}
        )
        alerts = (alerts_data or {}).get("alerts", [])
        log.info("ZAP: dohvaceno %d upozorenja", len(alerts))

        report_path = output_dir / "zap_report.json"
        try:
            report_path.write_text(
                json.dumps({"alerts": alerts}, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        except OSError as exc:
            log.warning("ZAP: zapis izvjestaja nije uspio: %s", exc)
            return None
        return report_path
