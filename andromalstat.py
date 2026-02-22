#!/usr/bin/env python3
"""
Ultimate Android Malware Analyzer (Stable & Enhanced)
Features:
- Hybrid Engine: Bytecode Tracing + Raw String Scraping
- Native Library (.so) Analysis
- Nested APK (Dropper) Detection
- Binary Manifest XML Decoding
"""

import sys
import os
import hashlib
import json
import zipfile
import math
import logging
import threading
import time
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# --- CONFIGURATION: Silence Androguard Logs ---
logging.getLogger("androguard").setLevel(logging.CRITICAL)
logging.getLogger("androguard.core.api_specific_resources").setLevel(logging.CRITICAL)

# --- DEPENDENCY CHECK ---
MISSING_DEPS = []
try:
    # STABLE IMPORT (Like Code 2)
    from androguard.misc import AnalyzeAPK
except ImportError:
    MISSING_DEPS.append("androguard")
try:
    import yara
except ImportError:
    MISSING_DEPS.append("yara-python")
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    MISSING_DEPS.append("colorama")
    class Fore: CYAN = GREEN = RED = YELLOW = RESET = ""

if MISSING_DEPS:
    print(f"[-] CRITICAL: Missing dependencies: {', '.join(MISSING_DEPS)}")
    print(f"[-] Run: pip install androguard yara-python colorama")
    sys.exit(1)

class UltimateAnalyzer:
    def __init__(self, apk_path, output_dir="analysis_result"):
        self.apk_path = Path(apk_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.data = {
            'meta': {
                'filename': self.apk_path.name,
                'timestamp': datetime.now().isoformat(),
                'tool': 'UltimateAnalyzer v2.0'
            },
            'file_info': {},
            'permissions': [],
            'components': {},
            'dangerous_apis': defaultdict(list),
            'secrets': defaultdict(list),
            'native_libs': [],
            'nested_apks': [],
            'yara_matches': [],
            'risk_score': 0,
            'findings': []
        }
        
        self.yara_rules = self._compile_yara()

    def _compile_yara(self):
        """Compiles YARA rules for malware signatures"""
        rules = """
        rule Suspicious_Banker {
            strings:
                $a = "WindowManager$LayoutParams"
                $b = "SYSTEM_ALERT_WINDOW"
                $c = "setTitle"
            condition:
                all of them
        }
        rule Ransomware_ Indicators {
            strings:
                $a = "decrypt" nocase
                $b = "locked" nocase
                $c = "tor browser" nocase
                $d = ".onion"
            condition:
                2 of them
        }
        rule Dropper_Payload {
            strings:
                $a = "assets/"
                $b = ".apk"
                $c = "DexClassLoader"
            condition:
                all of them
        }
        """
        try: return yara.compile(source=rules)
        except: return None

    def run(self):
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}[*] TARGET: {self.apk_path.name}")
        print(f"{Fore.CYAN}{'='*60}\n")

        # Phase 1: File Profiling (Hash + Entropy + Nested Check)
        self.step_file_profiling()

        # Phase 2: Androguard Loading
        if not self.step_load_androguard():
            return

        # Phase 3: Certificate & Manifest (Binary XML Decoding)
        self.step_manifest_and_cert()

        # Phase 4: Hybrid Code Analysis (The "Smart + Dumb" Scan)
        self.step_hybrid_code_analysis()

        # Phase 5: Native & Nested Check
        self.step_native_and_nested()

        # Phase 6: YARA
        self.step_yara()

        # Phase 7: Report
        self.step_report()

    def step_file_profiling(self):
        print(f"{Fore.GREEN}[+] Step 1: File Profiling")
        try:
            with open(self.apk_path, 'rb') as f:
                raw = f.read()
                md5 = hashlib.md5(raw).hexdigest()
                sha256 = hashlib.sha256(raw).hexdigest()
                
                # Entropy (Detection of Packing/Encryption)
                entropy = 0
                if len(raw) > 0:
                    counts = [raw.count(bytes([i])) for i in range(256)]
                    entropy = -sum(p * math.log2(p) for p in [c/len(raw) for c in counts] if p > 0)

            print(f"    MD5: {md5}")
            print(f"    Entropy: {entropy:.4f}")
            
            self.data['file_info'] = {'md5': md5, 'sha256': sha256, 'entropy': entropy, 'size': len(raw)}
            
            if entropy > 7.5:
                self._add_finding("HIGH Entropy (Likely Packed or Encrypted)", 20)
        except Exception as e:
            print(f"{Fore.RED}    Error reading file: {e}")

    def step_load_androguard(self):
        print(f"{Fore.YELLOW}[*] Step 2: Loading Analysis Engine...")
        
        done = False
        def animate():
            chars = "/—\|" 
            i = 0
            while not done:
                sys.stdout.write(f'\r    Processing Bytecode... {chars[i % len(chars)]}')
                sys.stdout.flush()
                time.sleep(0.1)
                i += 1
        
        t = threading.Thread(target=animate)
        t.daemon = True
        t.start()

        try:
            # This handles Binary XML and DEX parsing internally
            self.a, self.d, self.dx = AnalyzeAPK(str(self.apk_path))
            done = True
            print(f"\r    {Fore.GREEN}✓ Analysis Loaded Successfully!            ")
            return True
        except Exception as e:
            done = True
            print(f"\n{Fore.RED}[-] Analysis Failed: {e}")
            print(f"    (The APK might be corrupted or password protected)")
            return False

    def step_manifest_and_cert(self):
        print(f"{Fore.GREEN}[+] Step 3: Manifest & Certificate Analysis")
        
        # 3.1 Certificate
        if self.a.is_signed():
            for cert in self.a.get_certificates():
                # Fix for Androguard v4 returning objects
                issuer = cert.issuer.human_friendly if hasattr(cert.issuer, 'human_friendly') else str(cert.issuer)
                print(f"    Signer: {issuer}")
                if "Android Debug" in issuer:
                    self._add_finding("Signed with Debug Certificate (Test Key)", 30)
        else:
            self._add_finding("APK is not signed", 50)

        # 3.2 Permissions
        perms = self.a.get_permissions()
        dangerous = ['SEND_SMS', 'READ_SMS', 'RECEIVE_BOOT_COMPLETED', 'SYSTEM_ALERT_WINDOW', 'READ_CONTACTS', 'INSTALL_PACKAGES']
        found_danger = [p.split('.')[-1] for p in perms if any(d in p for d in dangerous)]
        
        if found_danger:
            print(f"    {Fore.RED}Dangerous Perms: {found_danger}")
            self._add_finding(f"Dangerous Permissions: {found_danger}", len(found_danger) * 10)
        
        self.data['permissions'] = perms

        # 3.3 Components (Activities/Services)
        # Androguard decodes the Binary XML automatically here
        components = {
            'activities': self.a.get_activities(),
            'services': self.a.get_services(),
            'receivers': self.a.get_receivers()
        }
        self.data['components'] = components
        print(f"    Activities: {len(components['activities'])}")
        print(f"    Services:   {len(components['services'])}")

        # 3.4 Persistence Check (Looking inside decoded XML)
        try:
            # We treat the XML as a string to grep for intents
            manifest_xml = str(self.a.get_android_manifest_xml()) 
            if "BOOT_COMPLETED" in manifest_xml:
                self._add_finding("Persistence: App auto-starts on boot", 25)
        except Exception:
            pass

    def step_hybrid_code_analysis(self):
        """Combines specific Bytecode tracing with broad String search"""
        print(f"{Fore.GREEN}[+] Step 4: Hybrid Code Analysis")
        
        # 4.1 Bytecode Scan (Accurate but fragile to obfuscation)
        suspicious_apis = {
            'Ljavax/crypto/Cipher;->getInstance': 'Encryption',
            'Ljava/lang/Runtime;->exec': 'Command Exec',
            'Landroid/telephony/SmsManager;->sendTextMessage': 'SMS Sending',
            'Ldalvik/system/DexClassLoader;->loadClass': 'Dynamic Loading'
        }
        
        bytecode_hits = 0
        try:
            for method in self.dx.get_methods():
                if method.is_external(): continue
                for instr in method.get_instructions():
                    code = instr.get_output()
                    for api, cat in suspicious_apis.items():
                        if api in code:
                            self.data['dangerous_apis'][cat].append(f"{method.class_name}::{method.name}")
                            bytecode_hits += 1
        except: pass

        # 4.2 Raw String Fallback (Catches obfuscated/split strings)
        print("    [Fallback] Scanning Raw Strings for hidden APIs & IOCs...")
        
        patterns = {
            'URL': r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s]*)?',
            'IP': r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            'C2_Domain': r'[a-zA-Z0-9\-]+\.(?:xyz|top|ru|cn|ga|tk)', 
            'Exec': r'Runtime\.exec',
            'SMS': r'sendTextMessage'
        }

        string_hits = defaultdict(set)
        for s in self.dx.get_strings():
            val = s.get_value()
            if len(val) > 500: continue 
            
            for key, pat in patterns.items():
                if re.search(pat, val):
                    string_hits[key].add(val)

        # 4.3 Merge Results
        if bytecode_hits == 0 and ('Exec' in string_hits or 'SMS' in string_hits):
            self._add_finding("Hidden APIs found in Strings (Obfuscation detected)", 25)
        
        for key, vals in string_hits.items():
            if vals:
                clean_vals = list(vals)[:10] # Limit output
                print(f"    Found {len(vals)} {key}s")
                self.data['secrets'][key] = clean_vals
                if key == 'C2_Domain':
                    self._add_finding(f"Suspicious C2 Domains: {clean_vals}", 40)

    def step_native_and_nested(self):
        print(f"{Fore.GREEN}[+] Step 5: Native & Nested Analysis")
        
        # Scan file list from the APK object
        for f in self.a.get_files():
            # 5.1 Native Libs
            if f.endswith(".so"):
                self.data['native_libs'].append(f)
                # Read binary content for shell commands
                try:
                    content = self.a.get_file(f)
                    if b"/bin/sh" in content or b"system" in content:
                        self._add_finding(f"Native Shell Payload in {f}", 35)
                except: pass

            # 5.2 Nested APKs (Droppers)
            if f.endswith(".apk") or (f.endswith(".dex") and "classes" not in f):
                print(f"    {Fore.RED}(!) Found Nested APK/DEX: {f}")
                self.data['nested_apks'].append(f)
                self._add_finding(f"Dropper Behavior: Nested APK found ({f})", 50)

        if self.data['native_libs']:
            print(f"    Native Libraries: {len(self.data['native_libs'])}")

    def step_yara(self):
        print(f"{Fore.GREEN}[+] Step 6: YARA Malware Signatures")
        if self.yara_rules:
            # Androguard lets us get raw bytes of the whole APK
            raw_apk = self.a.get_raw()
            matches = self.yara_rules.match(data=raw_apk)
            
            for m in matches:
                print(f"    {Fore.RED}MATCH: {m.rule}")
                self._add_finding(f"YARA Match: {m.rule}", 60)
                self.data['yara_matches'].append(m.rule)
        else:
            print("    YARA rules failed to compile.")

    def step_report(self):
        score = self.data['risk_score']
        if score > 80: risk = "CRITICAL"
        elif score > 40: risk = "HIGH"
        elif score > 15: risk = "MEDIUM"
        else: risk = "LOW"

        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"RISK ASSESSMENT: {risk} (Score: {score})")
        print(f"{'='*60}")
        
        for f in self.data['findings']:
            print(f" - {f}")

        json_path = self.output_dir / "analysis_report.json"
        with open(json_path, 'w') as f:
            json.dump(self.data, f, indent=2, default=str)
        print(f"\n[+] Detailed report saved to: {json_path}")

    def _add_finding(self, desc, points):
        self.data['findings'].append(desc)
        self.data['risk_score'] += points

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python andromalstat.py <apk_file>")
        sys.exit(1)
    
    target = sys.argv[1]
    if not os.path.exists(target):
        print(f"[-] File not found: {target}")
        sys.exit(1)

    UltimateAnalyzer(target).run()
