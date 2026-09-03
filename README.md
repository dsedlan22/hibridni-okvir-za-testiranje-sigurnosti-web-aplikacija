# Hibridni okvir za testiranje sigurnosti web aplikacija

Praktični dio završnog rada — okvir koji orkestrira tri alata otvorenog koda
(**OWASP ZAP**, **Nuclei**, **sqlmap**), normalizira njihove izlaze u jedinstveni
model nalaza, provodi deduplikaciju i korelaciju te generira objedinjeni JSON i HTML
izvještaj.

## Arhitektura (5 komponenti, pogl. 4.3)

| Komponenta | Datoteka(e) |
|---|---|
| Upravljački modul (Controller) | `main.py` |
| Wrapperi | `wrappers/` |
| Modul za normalizaciju | `normalizer.py` |
| Modul za korelaciju | `deduplicator.py` |
| Modul za izvještavanje | `reporters/` |

Jedinstveni model nalaza: `models/finding.py`. Parseri sirovih izlaza: `parsers/`.

## Okolina

- WSL2 Ubuntu, Python 3 u `.venv/`
- OWASP ZAP 2.17.0 kao daemon na `http://127.0.0.1:8090` (bez API keya), vođen REST API-jem preko `requests`
- Nuclei v3.11.1 i sqlmap 1.10.4 na PATH-u
- Meta: DVWA u Dockeru na `http://localhost:8081`, security razina *low*

## Pokretanje

```bash
cd "/mnt/c/Users/David/Documents/FAKS/Zavrsni_rad_okvir"
source .venv/bin/activate
pip install -r requirements.txt          # prvi put
python main.py --target http://localhost:8081
```

Preduvjeti prije pokretanja:
- DVWA container radi (`docker ps` prikazuje `dvwa`)
- ZAP daemon je gore (`curl -s http://127.0.0.1:8090/JSON/core/view/version/`)

Rezultati se zapisuju u `./rezultati/`:
- `izvjestaj.json`, `izvjestaj.html` — objedinjeni izvještaji
- `zap_report.json`, `nuclei_report.jsonl`, `sqlmap_*.txt` — sirovi izlazi
- `framework.log` — log izvođenja

## Argumenti

- `--target` — ciljni URL (nadjačava `config.yaml`)
- `--output-dir` — izlazni direktorij (default `./rezultati`)
- `--config` — putanja do configa (default `config.yaml`)

## Konfiguracija

Svi parametri (mete, alati, timeouti, sqlmap endpointi) zadaju se u `config.yaml`.
Alat se isključuje s `enabled: false`. Ako alat/daemon nije dostupan, okvir logira
upozorenje i nastavlja s ostalima.
