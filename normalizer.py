"""Normalizer - canonical vuln names, OWASP Top 10 mapping, Croatian severity scale (4.4/4.6)."""

from typing import List

from models.finding import Finding
from utils.logger import get_logger

KANON_NAZIVI = {
    "cross site scripting (reflected)": "Reflected XSS",
    "cross site scripting (persistent)": "Stored XSS",
    "cross site scripting (dom based)": "XSS",
    "reflected cross site scripting": "Reflected XSS",
    "sql injection": "SQL Injection",
}

OWASP_MAPA = {
    "sql injection": "A03:2021 Injection",
    "sqli": "A03:2021 Injection",
    "cross-site scripting": "A03:2021 Injection",
    "cross site scripting": "A03:2021 Injection",
    "xss": "A03:2021 Injection",
    "reflected xss": "A03:2021 Injection",
    "stored xss": "A03:2021 Injection",
    "command injection": "A03:2021 Injection",
    "os command injection": "A03:2021 Injection",
    "cross-site request forgery": "A01:2021 Broken Access Control",
    "csrf": "A01:2021 Broken Access Control",
    "insecure direct object reference": "A01:2021 Broken Access Control",
    "idor": "A01:2021 Broken Access Control",
    "security misconfiguration": "A05:2021 Security Misconfiguration",
    "sensitive data exposure": "A02:2021 Cryptographic Failures",
    "vulnerable components": "A06:2021 Vulnerable and Outdated Components",
    "outdated components": "A06:2021 Vulnerable and Outdated Components",
    "server-side request forgery": "A10:2021 Server-Side Request Forgery",
    "ssrf": "A10:2021 Server-Side Request Forgery",
}

OWASP_KLJUCNE = [
    ("anti-csrf", "A01:2021 Broken Access Control"),
    ("csrf", "A01:2021 Broken Access Control"),
    ("path traversal", "A01:2021 Broken Access Control"),
    ("directory traversal", "A01:2021 Broken Access Control"),
    ("sensitive information", "A02:2021 Cryptographic Failures"),
    ("information disclosure", "A02:2021 Cryptographic Failures"),
    ("banner information", "A02:2021 Cryptographic Failures"),
    ("timestamp disclosure", "A02:2021 Cryptographic Failures"),
    ("version information", "A05:2021 Security Misconfiguration"),
    ("x-content-type-options", "A05:2021 Security Misconfiguration"),
    ("content security policy", "A05:2021 Security Misconfiguration"),
    ("csp", "A05:2021 Security Misconfiguration"),
    ("clickjacking", "A05:2021 Security Misconfiguration"),
    ("directory browsing", "A05:2021 Security Misconfiguration"),
    ("security headers", "A05:2021 Security Misconfiguration"),
    ("cookie", "A05:2021 Security Misconfiguration"),
    ("private ip", "A05:2021 Security Misconfiguration"),
    ("phpinfo", "A05:2021 Security Misconfiguration"),
    ("configuration files", "A05:2021 Security Misconfiguration"),
    ("gitignore", "A05:2021 Security Misconfiguration"),
    ("readme", "A05:2021 Security Misconfiguration"),
    ("sub resource integrity", "A08:2021 Software and Data Integrity Failures"),
    ("cross-domain javascript", "A08:2021 Software and Data Integrity Failures"),
]

OZBILJNOST_MAPA = {
    "high": "visoko",
    "medium": "srednje",
    "low": "nisko",
    "informational": "informativno",
    "critical": "kritično",
    "info": "informativno",
    "kritično": "kritično",
    "visoko": "visoko",
    "srednje": "srednje",
    "nisko": "nisko",
    "informativno": "informativno",
}


class Normalizer:
    """Canonicalizes finding names, maps OWASP categories and translates severity."""

    def _kanon_naziv(self, naziv: str) -> str:
        """Return the canonical vulnerability name (or the original if unknown)."""
        n = (naziv or "").strip().lower()
        if n in KANON_NAZIVI:
            return KANON_NAZIVI[n]
        if n.startswith("sql injection"):
            return "SQL Injection"
        if "command injection" in n:
            return "OS Command Injection"
        return naziv

    def _owasp(self, naziv: str) -> str:
        """Map a vulnerability name to an OWASP Top 10 category."""
        n = (naziv or "").strip().lower()
        if n in OWASP_MAPA:
            return OWASP_MAPA[n]
        for kljuc, kategorija in OWASP_KLJUCNE:
            if kljuc in n:
                return kategorija
        return "nekategorizirano"

    def _ozbiljnost(self, ozb: str) -> str:
        """Translate a source severity value into the Croatian scale."""
        return OZBILJNOST_MAPA.get((ozb or "").strip().lower(), "informativno")

    def normalize(self, findings: List[Finding]) -> List[Finding]:
        """Normalize a list of findings in place and return it."""
        for f in findings:
            f.ranjivost = self._kanon_naziv(f.ranjivost)
            f.owasp_kategorija = self._owasp(f.ranjivost)
            f.ozbiljnost = self._ozbiljnost(f.ozbiljnost)
        get_logger().info("Normalizacija: obradeno %d nalaza", len(findings))
        return findings
