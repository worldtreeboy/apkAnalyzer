<div align="center">

# 🛡️ APK Analyzer

### The Only Android Security Tool You'll Ever Need

**Static analysis. Dynamic analysis. Frida instrumentation. Binary patching.**
**One tool. One terminal. Zero Python packages.**

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white)](https://python.org)
[![Release](https://img.shields.io/github/v/release/worldtreeboy/apkAnalyzer?sort=semver)](https://github.com/worldtreeboy/apkAnalyzer/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20WSL%20%7C%20macOS-lightgrey)]()
[![ADB](https://img.shields.io/badge/Requires-ADB%20%2B%20Root-orange)]()
[![Frida](https://img.shields.io/badge/Frida-Integrated-blueviolet?logo=frida)](https://frida.re)

<br>

**⭐ If this tool saves you time, [give it a star](https://github.com/worldtreeboy/apkAnalyzer) — it helps others find it!**

</div>

<br>

## 🚀 Get Started in 10 Seconds

```bash
git clone https://github.com/worldtreeboy/apkAnalyzer.git
cd apkAnalyzer
python3 apkAnalyzer.py
```

> **That's it.** No `pip install`, Docker, or config files. Install ADB (plus apktool for static scans), connect a rooted device, and go.

<br>

## 🎬 Demo

```
┌──────────────────────────────────────────────────────┐
│              APK Analyzer — Main Menu                 │
│         github.com/worldtreeboy/apkAnalyzer          │
├──────────────────────────────────────────────────────┤
│  Target: com.example.app (v2.1.0)                    │
│  Device: Pixel 6 (Android 14)                        │
├──────────────────────────────────────────────────────┤
│                                                      │
│   [1]  App Analysis          [7]  Logcat Monitor     │
│   [2]  Storage Audit         [8]  Frida CodeShare    │
│   [3]  Shell Access          [9]  Binary Patcher     │
│   [4]  Screenshot            [10] Frida Server       │
│   [5]  Security Scan         [11] Testcases          │
│   [6]  Keyboard Cache        [12] Runtime Check      │
│                                                      │
│   [a]  Switch App   [r] Export Report  [0] Exit       │
│                                                      │
└──────────────────────────────────────────────────────┘
```

```
═══════════════════════════════════════════════════════
  SECURITY SCAN — com.example.app
═══════════════════════════════════════════════════════

  [CRITICAL] Debuggable          android:debuggable="true"  (MASVS-RESILIENCE-1 | CWE-489)
  [HIGH]     allowBackup          No exclusion rules defined  (MASVS-STORAGE-1 | CWE-530)
  [PASS]     Cleartext Traffic    usesCleartextTraffic="false"
  [HIGH]     Exported Components  3 activities, 1 provider  (MASVS-PLATFORM-1 | CWE-926)
  [CRITICAL] Hardcoded Secrets    Found credential in config.xml (value redacted)  (MASVS-STORAGE-1 | CWE-798)
  [PASS]     Network Security     Custom config with certificate pins
  [HIGH]     APK Signing          v1-only — Janus (CVE-2017-13156)  (MASVS-RESILIENCE-2 | CWE-347)
  ...
  ═══════════════════════════════════════════════════════
  CRITICAL: 2  |  HIGH: 3  |  MEDIUM: 4  |  LOW: 2
  PASS: 11  FAIL: 5  WARN: 3
  Overall: CRITICAL RISK
═══════════════════════════════════════════════════════
```

> 📹 **Want to see it live?** Record your own session with [asciinema](https://asciinema.org) and share it!

<br>

## 💡 Why APK Analyzer?

Most Android security tools do **one thing** — a static scanner, a Frida wrapper, or a storage dumper. You end up with 10 terminals open, copying package names between tools.

**APK Analyzer replaces all of them.**

| | What You Get |
|:-:|---|
| 🔍 | **19 security checks** in one scan — everything MobSF flags, from `allowBackup` to Janus CVE |
| 🎣 | **38 Frida scripts** ready to inject — SSL bypass, root hiding, crypto monitoring |
| 🧬 | **Universal bypass script** — SSL + root + anti-tamper in a single file |
| 🔧 | **Binary patching** — Frida Gadget or LSPatch injection in one command |
| 📦 | **Zero Python packages** — pure Python stdlib, no pip, no Docker |
| ⚡ | **Smart caching** — decompile once, reuse across all tools, auto-invalidated when the app updates |
| 🚀 | **Batched ADB** — storage audit reads ~30 files per round-trip, 50× faster on big apps |
| 🔌 | **Multi-device support** — pick a device when several are connected, all commands follow |
| 🔎 | **Structured secret detection** — scans common Android source/config formats while excluding known public identifiers |
| 🤖 | **Framework-aware** — auto-detects Flutter, React Native, Kotlin and adjusts scans |

<br>

## 🆕 What's New in v1.6.0

- 🚦 **Failure-safe runtime analysis** — ADB, root, launch, and helper failures now produce explicit `INCONCLUSIVE` results instead of false passes or a misleading low-risk summary
- 🎯 **Android-aware manifest results** — SDK defaults, permission inheritance and strength, aliases, provider path permissions, deep links, task affinity, and Network Security Config precedence are evaluated more accurately
- 🔒 **Safer secret detection** — structured JSON, SharedPreferences XML, properties, source, smali, database URL, JWT, and PEM matching now redacts complete values while excluding known public identifiers
- 📦 **Hardened backup extraction** — traversal, symlinked output paths, duplicate entries, file/directory conflicts, case collisions, oversized payloads, and malformed archives are rejected before member extraction
- 🧠 **Trustworthy APK caching** — unverifiable caches are not reused, failed device pulls cannot fall back to stale local APKs, and local cache entries carry their own content identity
- 🧬 **Safer Frida instrumentation** — Gadget loading uses a static class initializer without corrupting `onCreate` register frames, and the universal bypass script has been reworked for guarded modern Frida APIs
- ✅ **Expanded regression coverage** — 67 tests cover failure states, manifest edge cases, archive confinement, secret redaction, cache provenance, and Gadget injection

<br>

## 🛡️ Reliability and Accuracy Safeguards

- **Failure-safe runtime results** — missing, offline, unauthorized, or disconnected devices and failed root/tool commands are reported as `INCONCLUSIVE`; unavailable evidence is never converted into a pass or a low-risk result
- **Manifest-aware classification** — omitted SDK defaults, explicit empty permissions, activity aliases, provider path permissions, effective task affinity, and enabled/exported deep-link filters are handled explicitly
- **Effective network policy** — Android version defaults (including Android 6) and Network Security Config precedence are considered when evaluating cleartext traffic
- **Bounded secret scanning** — JSON, SharedPreferences XML, properties, source, smali, and other common text formats are scanned up to 500 KB per file; values are redacted in terminal and report output
- **Public identifiers stay informational** — Firebase/Google Android API keys, AWS access-key IDs, and Twilio Account/API-key SIDs are not reported as credentials by themselves
- **Safer backup extraction** — symlink output roots, duplicate members, file/directory prefix conflicts, traversal paths, and destination-filesystem case collisions are rejected before any archive member is written
- **Safer cache and Gadget behavior** — decompile caches are not reused when device fingerprints cannot be verified, and Frida Gadget loading is injected through `<clinit>` without changing an activity's `onCreate` register frame

`PASS` means a check ran with the evidence it required. `INCONCLUSIVE` means the required device, manifest, command, or tool evidence was unavailable. Neither status proves that an application is free of vulnerabilities.

<br>

## 📋 All 12 Features

| # | Feature | What It Does |
|:-:|---------|-------------|
| 1 | **App Analysis** | Permissions, components, version info, framework detection, APK extraction |
| 2 | **Storage Audit** | SharedPrefs, SQLite, Realm DBs — scan for secrets, PII, and insecure file permissions |
| 3 | **Shell Access** | Interactive root shell with directory tracking |
| 4 | **Screenshot** | Capture device screen, save locally with timestamp |
| 5 | **Security Scan** | 19 static checks with OWASP MASVS mapping, CWE IDs, severity scoring ([details below](#-security-scan-19-checks)) |
| 6 | **Keyboard Cache** | Detect if keyboard apps cache plaintext input |
| 7 | **Logcat Monitor** | Real-time filtered log streaming with keyword highlighting |
| 8 | **Frida CodeShare** | 38 scripts across 10 categories — inject from menu ([details below](#-frida-codeshare-38-scripts)) |
| 9 | **Binary Patcher** | Frida Gadget injection or LSPatch/Xposed embedding ([details below](#-binary-patcher)) |
| 10 | **Frida Server** | USB/remote mode switching, port forwarding, auto server management |
| 11 | **Testcases** | Launch exported components with intent actions + extras, clipboard spy, dev URL finder, **adb backup extraction** |
| 12 | **Runtime Security Check** | ADB-based dynamic analysis with explicit inconclusive states: post-launch secret scanning, file permissions, exported component probing, clipboard/logcat leakage, WebView cache |
| r | **Report Export** | Export findings to JSON or HTML with severity badges, MASVS references, and CWE IDs (`--report json\|html`) |

<br>

---

<details>
<summary><h2>🔒 Security Scan (19 Checks)</h2></summary>

Static analysis of the decompiled APK and AndroidManifest.xml. Each finding is scored with **CRITICAL / HIGH / MEDIUM / LOW** severity, mapped to **OWASP MASVS v2.0** categories, and tagged with **CWE IDs**. Results are shown as **PASS / FAIL / WARN / INCONCLUSIVE** with an overall risk summary. If the manifest cannot be parsed, manifest-dependent checks are skipped without fabricated passes while bounded code/resource secret scanning continues.

<table>
<tr><th>Category</th><th>Check</th><th>What It Flags</th></tr>
<tr><td rowspan="4"><b>Manifest</b></td>
  <td>Debuggable</td><td><code>android:debuggable="true"</code></td></tr>
<tr><td>allowBackup</td><td>Backup enabled without exclusion rules</td></tr>
<tr><td>Exported Components</td><td>Non-launcher components exported without a demonstrably strong manifest permission; unknown permission strength is flagged for review</td></tr>
<tr><td>Dangerous Permissions</td><td>Informational review of CAMERA, LOCATION, SMS, RECORD_AUDIO, etc.</td></tr>
<tr><td rowspan="3"><b>Network</b></td>
  <td>Cleartext Traffic</td><td>Effective manifest, target-SDK, and network-config policy allows HTTP</td></tr>
<tr><td>Network Security Config</td><td>Production policy trusts user-installed CAs</td></tr>
<tr><td>Deeplinks</td><td>Custom URI schemes without validation</td></tr>
<tr><td rowspan="4"><b>Code</b></td>
  <td>Data Leakage</td><td>Hardcoded secrets in bounded XML, JSON, properties, environment, source, smali, and related text files</td></tr>
<tr><td>WebView JS Interface</td><td><code>addJavascriptInterface()</code> — XSS risk on SDK &lt; 17</td></tr>
<tr><td>Debug Logging</td><td><code>Log.v/d</code>, Timber, <code>console.log</code>, <code>debugPrint</code> in production</td></tr>
<tr><td>Broadcast Security</td><td><code>sendBroadcast()</code> without permission</td></tr>
<tr><td rowspan="4"><b>UI / Input</b></td>
  <td>FLAG_SECURE</td><td>Informational review for sensitive screens</td></tr>
<tr><td>Clipboard Exposure</td><td>Clipboard reads and writes that require manual exposure review</td></tr>
<tr><td>Keyboard Cache</td><td>Password input types and keyboard-learning hints</td></tr>
<tr><td>Tapjacking</td><td>Informational review of sensitive confirmation views</td></tr>
<tr><td rowspan="4"><b>Platform</b></td>
  <td>SDK Version</td><td><code>minSdk</code> &lt; 23 or <code>targetSdk</code> &lt; 35</td></tr>
<tr><td>PendingIntent</td><td>Missing <code>FLAG_IMMUTABLE</code> (Android 12+ hijacking)</td></tr>
<tr><td>Task Hijacking</td><td>Custom <code>taskAffinity</code> — StrandHogg attack</td></tr>
<tr><td>APK Signing</td><td>v1-only = Janus vulnerability (CVE-2017-13156). Checks v1/v2/v3/v4</td></tr>
</table>

</details>

<details>
<summary><h2>🔑 Secret Detection</h2></summary>

Both **Storage Audit** and **Security Scan** use structured, bounded matching rules to catch hardcoded credentials. Known public identifiers, public certificates, publishable Stripe keys, OAuth client IDs, and endpoint URLs are intentionally not classified as secrets. Matching values and detected PII are redacted before terminal/report previews are produced.

| Provider | Patterns |
|----------|----------|
| **Generic** | Passwords, API keys, tokens, JWTs, bearer tokens, encryption keys |
| **AWS** | Secret access keys and session tokens; `AKIA` access-key IDs alone are excluded |
| **Google / Firebase** | Assigned Firebase credentials and secrets; public `AIza` Android API keys are excluded |
| **Azure** | Storage keys, connection strings, client secrets |
| **Stripe / Payment** | `sk_live_`, `rk_live_`, PayPal, Braintree, Razorpay secrets |
| **Messaging** | Twilio auth tokens, SendGrid and Slack tokens, webhook URLs; Twilio Account/API-key SIDs are excluded |
| **GitHub** | `ghp_`/`ghs_` PATs, fine-grained tokens |
| **Database** | MongoDB, Postgres, MySQL, Redis connection strings |
| **Crypto** | PEM private keys |

</details>

<details>
<summary><h2>🧬 Custom Frida Script (Universal Bypass)</h2></summary>

`frida_scripts/universal_bypass.js` — a guarded all-in-one baseline for common **TLS pinning**, **root/emulator detection**, **anti-debug**, and **anti-Frida** checks. Spawn mode is recommended so hooks are installed before application code runs.

```bash
frida -U -f <package> -l frida_scripts/universal_bypass.js
```

| Layer | What It Bypasses |
|-------|-----------------|
| **TLS Pinning** | SSLContext/TrustManager, HostnameVerifier, OkHttp, Conscrypt, TrustKit, WebView SSL errors, plus exported OpenSSL/BoringSSL verification APIs in late-loaded modules |
| **Root / Emulator** | Exact root/emulator files and packages, Runtime/ProcessBuilder commands, Build fields, SystemProperties, developer settings, RootBeer, and native file/command/property APIs |
| **Runtime Tampering** | Frida port and tracked `/proc` probes, app-origin `strstr`/`fgets`/`readlink`, thread names, `ptrace`, Java debugger APIs, self-directed kill signals, and Java process termination |

The script uses Frida 17's current module APIs with a Frida 16 fallback, watches newly loaded TLS modules, avoids hard-coded offsets and architecture-specific patches, and exposes hook/bypass counters through `rpc.exports.status`. Feature families can be disabled in the `CONFIG` block when isolating compatibility issues.

No generic script can bypass server-side Play Integrity decisions, custom obfuscated RASP, or inlined/static native verification. Those checks need app-specific analysis and targeted hooks.

</details>

<details>
<summary><h2>🎣 Frida CodeShare (38 Scripts)</h2></summary>

Auto-starts `frida-server` on device. Run scripts from local files or the built-in library:

| Category | Scripts |
|----------|---------|
| **SSL Pinning Bypass** | Multi-Unpinning, Universal Android, Universal v2, Flutter TLS, OkHttp4 |
| **Root Detection Bypass** | fridantiroot, Multi-Library, RootBeer, Xamarin, freeRASP, Talsec |
| **Anti-Debug / Anti-Tamper** | Anti-Debug, USB Debug, Developer Mode, Anti-Frida |
| **Multi-Bypass** | SSL+Root+Emulator, Root+Emulator+SSL, OneRule |
| **Biometric / Auth** | Universal Biometric, Android 11+ Biometric |
| **Network Monitoring** | Traffic Interceptor, OkHttp3, TCP Trace |
| **Crypto Monitoring** | Crypto Monitor, AES Monitor, KeyStore Extractor |
| **Storage Monitoring** | SharedPrefs, EncryptedSharedPrefs, SQLite, File System, Clipboard |
| **Intent / WebView** | Intent Intercept, Deep Link Observer, WebView Debugger |
| **Tracing** | raptor Tracer, JNI Trace, List Classes, DEX Dump |

</details>

<details>
<summary><h2>🔧 Binary Patcher</h2></summary>

Two methods for non-rooted analysis:

### Frida Gadget

Injects `frida-gadget.so` into the APK for rootless dynamic analysis. The gadget is **auto-matched to the device ABI** (arm64/arm/x86/x86_64) **and your local Frida version** to avoid client/server mismatches.

```
Check deps → Detect ABI → Download gadget → Decompile → Patch manifest → Inject smali
→ Copy .so → Rebuild → Sign → Output: patched_apks/<pkg>_gadget_patched.apk
```

### LSPatch

Embeds [LSPosed/Xposed](https://github.com/LSPosed/LSPatch) framework into the APK — load Xposed modules without root.

```
Check java → Download LSPatch → Get APK → Patch
→ Output: patched_apks/
```

</details>

<details>
<summary><h2>🤖 Framework Detection</h2></summary>

Scans automatically detect the app framework and adjust keyword groups:

| Framework | How It's Detected | Impact |
|-----------|-------------------|--------|
| **Flutter** | `libflutter.so` | Adds Flutter security plugin keywords |
| **React Native** | `libreactnativejni.so`, `libhermes.so` | Adds RN keywords, scans `.bundle` files |
| **Kotlin** | `kotlin/` in smali | Java/Kotlin keyword coverage |
| **Java** | Default fallback | Default keyword coverage |

Native security SDKs (VKey, Zimperium, Promon, DexGuard) are detected from `.so` files on every scan.

</details>

---

## 📊 Report Export

Export findings to JSON or self-contained HTML reports with severity badges, MASVS references, and CWE IDs:

```bash
python3 apkAnalyzer.py --report html --output report.html
python3 apkAnalyzer.py --report json --output findings.json
```

Or use the `[r] Export Report` menu option during an interactive session. HTML reports include color-coded severity badges, device info, and a findings summary table.

---

## 📦 Requirements

| Requirement | Required | Notes |
|-------------|:--------:|-------|
| Python 3.8+ | **Yes** | No pip packages needed |
| ADB | **Yes** | Must be in PATH (checked at startup) |
| Rooted device | **Yes** | Connected via USB; multiple devices supported |
| `apktool` | **Yes** | [Install guide](https://ibotpeaches.github.io/Apktool/) |
| `apksigner` | Optional | For APK signing scheme check |
| `frida` + `frida-tools` | Optional | For Frida scripts |
| `strings` (binutils) | Optional | Native lib string scan; pure-Python fallback included |

---

## 📁 Output Structure

```
./extracted_apks/      ← Pulled APKs from device
./patched_apks/        ← Frida Gadget / LSPatch output
./screenshots/         ← Device screenshots
./backups/             ← adb backup .ab files + unpacked app data
./.gadget_cache/       ← Cached Frida Gadget & LSPatch jar
./.apkanalyzer_tmp/    ← Decompiled APK cache (reused across scans)
```

---

## 🧪 Regression Tests

The runtime application uses only the Python standard library. Run the full regression suite with Python 3.8 or newer:

```bash
python -m unittest discover -s tests -v
```

If `pytest` is installed, the equivalent concise run is:

```bash
PYTHONPATH=. pytest -q
```

The suite uses deterministic ADB/tool mocks and temporary APK/backup fixtures, so it does not require a connected Android device. To syntax-check the bundled universal Frida script when Node.js is available:

```bash
node --check frida_scripts/universal_bypass.js
```

---

## 🤝 Contributing

Contributions are welcome! Feel free to [open an issue](https://github.com/worldtreeboy/apkAnalyzer/issues) or submit a pull request.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<div align="center">

### ⭐ Found this useful?

**If APK Analyzer saved you time, [star this repo](https://github.com/worldtreeboy/apkAnalyzer)** — it helps other security researchers discover it.

<br>

[![Star History Chart](https://api.star-history.com/svg?repos=worldtreeboy/apkAnalyzer&type=Date)](https://star-history.com/#worldtreeboy/apkAnalyzer&Date)

</div>
