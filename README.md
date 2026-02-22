<div align="center">

# Andro-MalStat

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
- [Analysis Phases](#analysis-phases)
- [Adding YARA Rules](#adding-yara-rules)
- [API Reference](#api-reference)
- [Deployment](#deployment)
- [License](#license)

 > [!TIP]
> #### Prefer the terminal? Also check out the [Andro-Malstat CLI](https://github.com/gigachad80/Andro-Malstat-CLI) for automation
  
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


## Analysis Phases

### Phase 1: File Profiling
- MD5, SHA1, SHA256 hash calculation
- File size and entropy analysis
- Packing/encryption detection

### Phase 2: Androguard Loading
- DEX bytecode parsing
- Animated progress indicator
- Fallback for corrupted APKs

### Phase 3: Manifest & Certificate
- Certificate chain validation
- Debug certificate detection
- Dangerous permission enumeration
- Component analysis (activities, services, receivers, providers)
- Boot persistence detection

### Phase 4: Obfuscation Detection
- ProGuard/R8 detection via class name entropy
- Average name length calculation
- Obfuscation ratio metrics

### Phase 5: Hybrid Code Analysis
- Bytecode API tracing for accurate detection
- Raw string pattern matching for obfuscated code
- Detection of:
  - Encryption APIs
  - Command execution
  - SMS operations
  - Dynamic code loading
  - Reflection usage
  - Admin abuse

### Phase 6: Native & Nested Analysis
- Native library (.so) enumeration
- Shell payload detection in native code
- Nested APK/DEX dropper identification

### Phase 7: Network Security Config
- network_security_config.xml parsing
- Cleartext traffic permission detection
- MITM vulnerability assessment

### Phase 8: Anti-Analysis Detection
- Debugger detection
- Emulator detection
- Root detection
- Frida/instrumentation detection

### Phase 9: YARA Scan
- Malware signature matching
- Severity-based scoring
- Custom rule support

### Phase 10: Final Report
- Risk score calculation
- Severity classification (CRITICAL, HIGH, MEDIUM, LOW)
- JSON report generation
260130_143022.json



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

yara_rules/
│   ├── ania-analysis.yar
│   ├── bank_overlay.yar
│   ├── clayrat.yar
│   ├── commercial.yar
│   ├── craxs.yar
│   ├── crypto.yar
│   ├── cypher.yar
│   ├── dropper.yar
│   ├── joker.yar
│   ├── lemon.yar
│   ├── ransomware.yar
│   ├── rat888.yar
│   ├── spynote.yar
│   └── venom_rat.yar

### Built-in YARA Rules

If no `yara_rules/` directory exists, the tool uses these internal signatures:

- **Suspicious_Overlay_Attack** - Banking trojan overlay patterns
- **APK_Dropper_Payload** - Nested APK detection
- **Native_Shell_Execution** - Shell command execution
- **Crypto_Ransomware_Pattern** - Encryption operations

### Custom YARA Rules Format

```yara
rule Your_Custom_Rule {
    meta:
        description = "Description of the malware"
        severity = "high"  // critical, high, medium, low
    strings:
        $a = "malicious_string"
        $b = "suspicious_api"
    condition:
        any of them
}
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

GNU - AGPL 3.0

---

**Made with Python** - Advanced static analysis for Android security research.


--- 

Contact : pookielinuxuser@tutamail.com

First Released : February 22nd 2026

Last updated : February 22nd 2026
