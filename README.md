<div align="center">

# APK Analyzer

**All-in-one Android security analysis toolkit for penetration testers and security researchers.**

Decompile, scan, audit, patch, and hook Android apps — all from a single interactive terminal.

[![Python](https://img.shields.io/badge/Python-3.6+-3776AB?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20WSL%20%7C%20macOS-lightgrey)]()
[![ADB](https://img.shields.io/badge/Requires-ADB%20%2B%20Root-orange)]()
[![Frida](https://img.shields.io/badge/Frida-Integrated-blueviolet?logo=frida)](https://frida.re)

</div>

---

## Why APK Analyzer?

Most Android security tools do **one thing** — a static scanner, a Frida wrapper, or a storage dumper. APK Analyzer combines **static analysis, dynamic analysis, Frida instrumentation, and binary patching** into a single workflow. Select your target app once, then run any of the 11 tools without switching between terminals.

- **Zero Python dependencies** — pure stdlib, runs anywhere with Python 3.6+
- **19-check security scan** — covers everything MobSF flags, from `allowBackup` to Janus CVE
- **38 Frida scripts** — SSL bypass, root hiding, crypto monitoring, and more — ready to go
- **Binary patching** — inject Frida Gadget or embed LSPosed/Xposed in one command
- **Smart caching** — decompiles once, reuses across all scans

---

## Quick Start

```bash
# 1. Connect a rooted Android device via USB
adb devices

# 2. Run it
python3 apkAnalyzer.py

# 3. Select your target app and go
```

> **That's it.** No `pip install`, no Docker, no config files. Frida server starts automatically.

---

## Features

| # | Feature | Description |
|:-:|---------|-------------|
| 1 | **App Analysis** | Permissions, components, version info, framework detection, APK extraction |
| 2 | **Storage Audit** | Scan SharedPrefs, SQLite, Realm DBs for secrets & PII. File permission checks. EncryptedSharedPreferences detection |
| 3 | **Shell Access** | Interactive root shell with directory tracking |
| 4 | **Screenshot** | Capture device screen, save locally with timestamp |
| 5 | **Security Scan** | 19 static checks with PASS/FAIL/WARN scoring ([details below](#security-scan-19-checks)) |
| 6 | **Keyboard Cache** | Detect if LokiBoard caches plaintext input |
| 7 | **Logcat Monitor** | Real-time filtered log streaming with keyword highlighting |
| 8 | **Frida CodeShare** | 38 pre-configured scripts across 10 categories ([details below](#frida-codeshare-38-scripts)) |
| 9 | **Binary Patcher** | Frida Gadget injection or LSPatch (Xposed) embedding ([details below](#binary-patcher)) |
| 10 | **Frida Server Config** | USB/remote mode switching, port forwarding, server management |
| 11 | **Testcases** | Launch exported components with intent actions + extras, clipboard spy, dev URL finder |

---

## Security Scan (19 Checks)

Static analysis of the decompiled APK and AndroidManifest.xml. Results scored as PASS / FAIL / WARN.

<table>
<tr><th>Category</th><th>Check</th><th>What It Flags</th></tr>
<tr><td rowspan="4"><b>Manifest</b></td>
  <td>Debuggable</td><td><code>android:debuggable="true"</code></td></tr>
<tr><td>allowBackup</td><td>Backup enabled without exclusion rules</td></tr>
<tr><td>Exported Components</td><td>Activities, services, receivers, providers with <code>exported="true"</code></td></tr>
<tr><td>Dangerous Permissions</td><td>CAMERA, LOCATION, SMS, RECORD_AUDIO, etc.</td></tr>
<tr><td rowspan="3"><b>Network</b></td>
  <td>Cleartext Traffic</td><td><code>usesCleartextTraffic="true"</code></td></tr>
<tr><td>Network Security Config</td><td>Missing config or trusts user CAs</td></tr>
<tr><td>Deeplinks</td><td>Custom URI schemes without validation</td></tr>
<tr><td rowspan="4"><b>Code</b></td>
  <td>Data Leakage</td><td>Hardcoded secrets in XML, JSON, YAML, properties</td></tr>
<tr><td>WebView JS Interface</td><td><code>addJavascriptInterface()</code> — XSS risk on SDK &lt; 17</td></tr>
<tr><td>Debug Logging</td><td><code>Log.v/d</code>, Timber, <code>console.log</code>, <code>debugPrint</code> in production</td></tr>
<tr><td>Broadcast Security</td><td><code>sendBroadcast()</code> without permission</td></tr>
<tr><td rowspan="4"><b>UI / Input</b></td>
  <td>FLAG_SECURE</td><td>Missing screenshot protection</td></tr>
<tr><td>Clipboard Exposure</td><td><code>ClipboardManager</code> without <code>FLAG_SENSITIVE</code></td></tr>
<tr><td>Keyboard Cache</td><td>Missing <code>textPassword</code> / <code>textNoSuggestions</code></td></tr>
<tr><td>Tapjacking</td><td>Missing <code>filterTouchesWhenObscured</code></td></tr>
<tr><td rowspan="4"><b>Platform</b></td>
  <td>SDK Version</td><td><code>minSdk</code> &lt; 23 or <code>targetSdk</code> &lt; 30</td></tr>
<tr><td>PendingIntent</td><td>Missing <code>FLAG_IMMUTABLE</code> (Android 12+ hijacking)</td></tr>
<tr><td>Task Hijacking</td><td>Custom <code>taskAffinity</code> — StrandHogg attack</td></tr>
<tr><td>APK Signing</td><td>v1-only = Janus vulnerability (CVE-2017-13156). Checks v1/v2/v3/v4</td></tr>
</table>

---

## Secret Detection

Both **Storage Audit** and **Security Scan** use ~40 regex patterns to catch hardcoded secrets:

| Provider | Patterns |
|----------|----------|
| **Generic** | Passwords, API keys, tokens, JWTs, bearer tokens, encryption keys |
| **AWS** | `AKIA` access keys, secret keys, session tokens, S3 URLs |
| **Google / Firebase** | `AIza` keys, Firebase secrets, OAuth client IDs |
| **Azure** | Storage keys, connection strings, tenant secrets |
| **Stripe / Payment** | `sk_live_`, `pk_live_`, PayPal, Braintree, Razorpay |
| **Messaging** | Twilio, SendGrid, Slack tokens, webhook URLs |
| **GitHub** | `ghp_`/`ghs_` PATs, fine-grained tokens |
| **Database** | MongoDB, Postgres, MySQL, Redis connection strings |
| **Crypto** | PEM private keys, certificates |

---

## Frida CodeShare (38 Scripts)

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

---

## Binary Patcher

Two methods for non-rooted analysis:

### Frida Gadget

Injects `frida-gadget.so` into the APK for rootless dynamic analysis.

```
Check deps → Download gadget → Decompile → Patch manifest → Inject smali
→ Copy .so → Rebuild → Sign → Output: patched_apks/<pkg>_gadget_patched.apk
```

### LSPatch

Embeds [LSPosed/Xposed](https://github.com/LSPosed/LSPatch) framework into the APK — load Xposed modules without root.

```
Check java → Download LSPatch → Get APK → Patch
→ Output: patched_apks/
```

---

## Framework Detection

Scans automatically detect the app framework and adjust keyword groups:

| Framework | How It's Detected | Impact |
|-----------|-------------------|--------|
| **Flutter** | `libflutter.so` | Adds Flutter security plugin keywords |
| **React Native** | `libreactnativejni.so`, `libhermes.so` | Adds RN keywords, scans `.bundle` files |
| **Kotlin** | `kotlin/` in smali | Java/Kotlin keyword coverage |
| **Java** | Default fallback | Default keyword coverage |

Native security SDKs (VKey, Zimperium, Promon, DexGuard) are detected from `.so` files on every scan.

---

## Requirements

| Requirement | Required | Notes |
|-------------|:--------:|-------|
| Python 3.6+ | Yes | No pip packages needed |
| ADB | Yes | Must be in PATH |
| Rooted device | Yes | Connected via USB |
| `apktool` | Yes | [Install](https://ibotpeaches.github.io/Apktool/) — required for decompilation |
| `apksigner` | Optional | Android SDK build-tools — for APK signing scheme check |
| `frida` + `frida-tools` | Optional | For Frida CodeShare scripts |

---

## How It Works

```
python3 apkAnalyzer.py
```

1. Connects to device via ADB, starts `frida-server` automatically
2. Lists third-party apps (`pm list packages -3`), you pick your target
3. All 11 features operate on the selected app — press `[a]` to switch anytime

```
./extracted_apks/      ← Extracted APKs
./patched_apks/        ← Patched APKs (Gadget / LSPatch)
./screenshots/         ← Device screenshots
./.gadget_cache/       ← Frida Gadget & LSPatch jar cache
./.apkanalyzer_tmp/    ← Decompiled APK cache (reused across scans)
```

---

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

<div align="center">

**If this tool helped you, consider giving it a star to help others find it!**

</div>
