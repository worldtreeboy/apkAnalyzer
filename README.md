<div align="center">

# 🛡️ APK Analyzer

### The Only Android Security Tool You'll Ever Need

**Static analysis. Dynamic analysis. Frida instrumentation. Binary patching.**
**One tool. One terminal. Zero dependencies.**

[![Python](https://img.shields.io/badge/Python-3.6+-3776AB?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20WSL%20%7C%20macOS-lightgrey)]()
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

> **That's it.** No `pip install`. No Docker. No config files. Just plug in a rooted device and go.

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
  [CRITICAL] Hardcoded Secrets    Found AWS key in config.xml  (MASVS-STORAGE-1 | CWE-798)
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
| 📦 | **Zero dependencies** — pure Python stdlib, no pip, no Docker |
| ⚡ | **Smart caching** — decompile once, reuse across all 11 tools |
| 🔎 | **~40 secret patterns** — catches AWS, Firebase, Stripe, GitHub tokens & more |
| 🤖 | **Framework-aware** — auto-detects Flutter, React Native, Kotlin and adjusts scans |

<br>

## 📋 All 11 Features

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
| 11 | **Testcases** | Launch exported components with intent actions + extras, clipboard spy, dev URL finder |
| 12 | **Runtime Security Check** | ADB-based dynamic analysis: post-launch secret scanning, file permissions, exported component probing, clipboard/logcat leakage, WebView cache |
| r | **Report Export** | Export findings to JSON or HTML with severity badges, MASVS references, and CWE IDs (`--report json\|html`) |

<br>

---

<details>
<summary><h2>🔒 Security Scan (19 Checks)</h2></summary>

Static analysis of the decompiled APK and AndroidManifest.xml. Each finding is scored with **CRITICAL / HIGH / MEDIUM / LOW** severity, mapped to **OWASP MASVS v2.0** categories, and tagged with **CWE IDs**. Results also shown as **PASS / FAIL / WARN** with an overall risk summary.

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

</details>

<details>
<summary><h2>🔑 Secret Detection (~40 Patterns)</h2></summary>

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

</details>

<details>
<summary><h2>🧬 Custom Frida Script (Universal Bypass)</h2></summary>

`frida_scripts/universal_bypass.js` — a single all-in-one script that bypasses **SSL pinning**, **root detection**, and **runtime tampering** simultaneously. More comprehensive than any individual CodeShare script.

```bash
frida -U -f <package> -l frida_scripts/universal_bypass.js
```

| Layer | What It Bypasses |
|-------|-----------------|
| **SSL Pinning** | TrustManager, TrustManagerFactory, HostnameVerifier, OkHttp3 CertificatePinner (+ proguarded), Conscrypt, TrustKit, WebView SSL, Flutter BoringSSL, Apache HTTP |
| **Root Detection** | File.exists (30+ paths), PackageManager (20+ root packages), Runtime.exec, ProcessBuilder, Build.TAGS, SystemProperties, RootBeer library, native fopen/access/stat |
| **Runtime Tampering** | Anti-Frida (port 27042, /proc/maps, native strstr), anti-debug (ptrace, TracerPid spoofing), System.exit blocking, emulator detection, Xposed detection, process kill prevention |

Every hook is wrapped in try/catch — if a class isn't present, it silently skips instead of crashing. Unique class names prevent collision on script reload.

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
| Python 3.6+ | **Yes** | No pip packages needed |
| ADB | **Yes** | Must be in PATH |
| Rooted device | **Yes** | Connected via USB |
| `apktool` | **Yes** | [Install guide](https://ibotpeaches.github.io/Apktool/) |
| `apksigner` | Optional | For APK signing scheme check |
| `frida` + `frida-tools` | Optional | For Frida scripts |

---

## 📁 Output Structure

```
./extracted_apks/      ← Pulled APKs from device
./patched_apks/        ← Frida Gadget / LSPatch output
./screenshots/         ← Device screenshots
./.gadget_cache/       ← Cached Frida Gadget & LSPatch jar
./.apkanalyzer_tmp/    ← Decompiled APK cache (reused across scans)
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
