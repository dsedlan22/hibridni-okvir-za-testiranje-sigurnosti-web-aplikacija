"""Controller - entry point orchestrating the hybrid security testing framework."""

import argparse
import time
from pathlib import Path
from typing import List

import yaml

from deduplicator import Deduplicator
from models.finding import Finding
from normalizer import Normalizer
from parsers import nuclei_parser, sqlmap_parser, zap_parser
from reporters import HTMLReporter, JSONReporter
from utils.dvwa_auth import get_cookie
from utils.logger import setup_logger
from wrappers import NucleiWrapper, SqlmapWrapper, ZapWrapper


def load_config(path: Path) -> dict:
    """Load the YAML configuration file."""
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    p = argparse.ArgumentParser(description="Hibridni okvir za testiranje sigurnosti web aplikacija")
    p.add_argument("--target", help="Ciljni URL (nadjacava config)")
    p.add_argument("--output-dir", default=None, help="Izlazni direktorij (default: ./rezultati)")
    p.add_argument("--config", default="config.yaml", help="Putanja do config.yaml")
    return p.parse_args()


def main() -> None:
    """Run the full orchestration pipeline."""
    start = time.time()
    args = parse_args()

    config = load_config(Path(args.config))
    target = args.target or config.get("target", "http://localhost:8081")
    output_dir = Path(args.output_dir or config.get("output_dir", "./rezultati"))
    output_dir.mkdir(parents=True, exist_ok=True)

    log = setup_logger(output_dir)
    log.info("=== Hibridni okvir - pokretanje ===")
    log.info("Meta: %s | Izlaz: %s", target, output_dir)

    tools_cfg = config.get("tools", {})
    dvwa_cfg = config.get("dvwa", {})

    def svjezi_sid() -> str:
        """Fetch a fresh authenticated DVWA session for the next tool.

        Svaki alat dobiva vlastitu sesiju jer ZAP tijekom skena posjeti
        logout.php i odjavio bi zajednicki kolacic za alate koji slijede.
        """
        return get_cookie(
            base_url=dvwa_cfg.get("base_url", target),
            username=dvwa_cfg.get("username", "admin"),
            password=dvwa_cfg.get("password", "password"),
            security_level=dvwa_cfg.get("security_level", "low"),
        )

    svi_nalazi: List[Finding] = []
    koristeni_alati: List[str] = []

    # 4/5. ZAP
    zap_cfg = tools_cfg.get("zap", {})
    if zap_cfg.get("enabled"):
        koristeni_alati.append("OWASP ZAP")
        raw = ZapWrapper(zap_cfg).run(target, output_dir, sid=svjezi_sid())
        svi_nalazi += zap_parser.parse(raw)

    # Nuclei
    nuclei_cfg = tools_cfg.get("nuclei", {})
    if nuclei_cfg.get("enabled"):
        koristeni_alati.append("Nuclei")
        raw = NucleiWrapper(nuclei_cfg).run(target, output_dir, sid=svjezi_sid())
        svi_nalazi += nuclei_parser.parse(raw)

    # sqlmap
    sqlmap_cfg = tools_cfg.get("sqlmap", {})
    if sqlmap_cfg.get("enabled"):
        koristeni_alati.append("sqlmap")
        pairs = SqlmapWrapper(sqlmap_cfg).run(target, output_dir, sid=svjezi_sid())
        for full_url, raw_path in (pairs or []):
            svi_nalazi += sqlmap_parser.parse(raw_path, full_url)

    total_raw = len(svi_nalazi)
    log.info("Prikupljeno ukupno %d sirovih nalaza", total_raw)

    # 7. normalizacija
    Normalizer().normalize(svi_nalazi)

    # 8. deduplikacija + korelacija
    jedinstveni = Deduplicator().deduplicate(svi_nalazi)

    # 9. izvjestaji
    elapsed = time.time() - start
    JSONReporter().generate(jedinstveni, output_dir, target, koristeni_alati, total_raw, elapsed)
    HTMLReporter().generate(jedinstveni, output_dir, target, koristeni_alati, total_raw, elapsed)

    # 10. sazetak
    po_alatu = {}
    for f in jedinstveni:
        for a in f.alati:
            po_alatu[a] = po_alatu.get(a, 0) + 1
    korelirano = sum(1 for f in jedinstveni if f.korelirano)

    log.info("=== Sazetak ===")
    for alat, broj in po_alatu.items():
        log.info("  %s: %d nalaza", alat, broj)
    log.info("  Ukupno sirovo: %d", total_raw)
    log.info("  Jedinstveno (dedup): %d", len(jedinstveni))
    log.info("  Korelirano: %d", korelirano)
    log.info("  Vrijeme: %.1f s", elapsed)
    log.info("=== Gotovo ===")


if __name__ == "__main__":
    main()
