<div align="center">

# Andro-MalStat WebUI

**Static analysis engine for Android APKs.**

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-Backend-000000?style=flat-square&logo=flask)
![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=flat-square&logo=sqlite&logoColor=white)
![YARA](https://img.shields.io/badge/YARA-Signatures-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

Upload an APK, get a full malware triage report — permissions, dangerous APIs, embedded secrets, native payloads, dropper detection, and YARA signature matching. Results persist across restarts.

---

</div>

## Table of Contents

- [Features](#features)
- [Stack](#stack)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [Adding YARA Rules](#adding-yara-rules)
- [Project Structure](#project-structure)
- [Deployment](#deployment)
- [License](#license)

## Features

- **Hybrid code analysis** — bytecode tracing + raw string scraping catches obfuscated malware that single-method scanners miss
- **14 YARA signatures** — SpyNote, Joker, CraxsRAT, Venom/Metasploit, ransomware, banking overlays, and more (extensible via `yara_rules/`)
- **Native library inspection** — detects shell payloads inside `.so` files
- **Dropper detection** — finds nested APKs and hidden DEX files
- **Risk scoring** — weighted findings produce a CRITICAL / HIGH / MEDIUM / LOW verdict
- **Persistent storage** — SQLite-backed, every scan is saved and exportable as JSON
- **Async architecture** — non-blocking uploads, background analysis, polling-based status

## Stack

| Layer | Tech |
|-------|------|
| Backend | Flask, SQLAlchemy, SQLite |
| Analysis | Androguard, YARA |
| Frontend | Vanilla HTML/CSS/JS |
| Production | Gunicorn (Linux) / Waitress (Windows) |

## Quick Start

```bash
git clone https://github.com/gigachad80/Andro-MalStat-WebUI.git
cd Andro-MalStat-WebUI
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000`. Upload an APK. Wait for the report.

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/scan` | Upload APK, returns `job_id` |
| `GET` | `/status/<job_id>` | Poll scan progress |
| `GET` | `/scans` | List all past scans |
| `GET` | `/export/<scan_id>` | Download JSON report |
| `GET` | `/health` | Server status |

## Adding YARA Rules

Drop `.yar` files into `yara_rules/`. They load automatically on next scan — no restart needed.

```
yara_rules/
  spynote.yar
  joker.yar
  your_custom_rule.yar
```

## Project Structure

```
app.py                    # Flask server + routes
config.py                 # DB and upload configuration
models.py                 # ScanResult SQLAlchemy model
ultimate_apk_analyzer.py  # Analysis engine
index.html                # Frontend (single-page)
yara_rules/               # External YARA signatures
Procfile                  # Gunicorn deployment
requirements.txt          # Python dependencies
malstat.db                # SQLite database (auto-created)
```

## Deployment

**Linux/Cloud**
```bash
gunicorn app:app --bind 0.0.0.0:5000 --workers 2 --threads 4
```

**Windows Server**
```bash
waitress-serve --port=5000 app:app
```

## License

GNU-AGPL 3.0

## Contact : 

pookielinuxuser@tutamail.com
