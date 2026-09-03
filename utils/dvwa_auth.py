"""DVWA authentication helper - obtains a PHPSESSID with the wanted security level."""

import re
from typing import Optional

import requests

from utils.logger import get_logger

TOKEN_RE = re.compile(r"name=['\"]user_token['\"]\s+value=['\"]([0-9a-fA-F]+)['\"]")


def _extract_token(html: str) -> Optional[str]:
    """Extract the DVWA anti-CSRF user_token from an HTML page."""
    match = TOKEN_RE.search(html)
    if match:
        return match.group(1)
    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html, "html.parser")
        tag = soup.find("input", {"name": "user_token"})
        if tag and tag.get("value"):
            return tag["value"]
    except Exception:
        pass
    return None


def get_cookie(base_url: str, username: str, password: str, security_level: str) -> str:
    """Log into DVWA, set the security level and return the PHPSESSID value."""
    log = get_logger()
    base_url = base_url.rstrip("/")
    session = requests.Session()

    try:
        resp = session.get(f"{base_url}/login.php", timeout=30)
        token = _extract_token(resp.text)
        if not token:
            log.warning("DVWA: user_token nije pronaden na login.php")
            return session.cookies.get("PHPSESSID", "")

        session.post(
            f"{base_url}/login.php",
            data={
                "username": username,
                "password": password,
                "user_token": token,
                "Login": "Login",
            },
            timeout=30,
        )

        resp = session.get(f"{base_url}/security.php", timeout=30)
        token = _extract_token(resp.text)
        if token:
            session.post(
                f"{base_url}/security.php",
                data={
                    "security": security_level,
                    "user_token": token,
                    "seclev_submit": "Submit",
                },
                timeout=30,
            )
        else:
            log.warning("DVWA: user_token nije pronaden na security.php")

        sid = session.cookies.get("PHPSESSID", "")
        if sid:
            log.info("DVWA prijava uspjesna, PHPSESSID dohvacen (razina: %s)", security_level)
        else:
            log.warning("DVWA: PHPSESSID kolacic nije dobiven")
        return sid
    except requests.RequestException as exc:
        log.warning("DVWA prijava nije uspjela: %s", exc)
        return ""
