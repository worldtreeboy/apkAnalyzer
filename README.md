# APK Analyzer

Android security analysis tools powered by ADB with root access.

---

## APK Analyzer

Interactive terminal menu for app analysis, storage auditing, shell access, screenshots, security scanning, OWASP MASVS compliance testing, and Frida integration.

**Target app is selected once at startup** — all features operate on the selected app. Press `[a]` from the menu to switch to a different app at any time.

### Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | **App Analysis** | View permissions, components, version info, extract APK |
| 2 | **Storage Audit** | Scan app data directories for SharedPreferences secrets, SQLite databases, cache |
| 3 | **Shell Access** | Interactive root shell via `su -c` |
| 4 | **Screenshot** | Capture device screen and save locally |
| 5 | **Security Scan** | Debuggable flag, allowBackup, exported components, dangerous permissions, SDK version, cleartext traffic, data leakage, deeplinks, WebView JS interface, PendingIntent mutability, implicit broadcast detection |
| 6 | **Keyboard Cache Detection** | Check if LokiBoard keyboard caches user input in plaintext. Prompts user to type in the app, then searches all `lokiboard_files_*.txt` cache files for the entered text |
| 7 | **Logcat Live Monitor** | Stream `adb logcat` in real-time filtered by a search string. Matched text highlighted in bold red. Ctrl+C to stop |
| 8 | **Frida CodeShare** | Auto-start frida-server (USB default), run local bypass scripts or 38 grouped CodeShare scripts (see below) |
| 9 | **Frida Server Config** | Switch between USB (`-U`) and custom host:port (`-H ip:port`), restart/kill frida-server, set up ADB port forwarding |
| 10 | **MASVS-STORAGE Assessment** | OWASP MASVS-STORAGE L1 compliance — 10 test cases across static + dynamic analysis (see below) |
| 11 | **Testcases for Fun** | Launch exported activities/services/receivers, clipboard spy, dev/staging URL finder (see below) |

### Auto Frida Server

On startup (with root), the analyzer automatically:
1. Kills any existing frida-server process
2. Starts frida-server on default USB port (`-U`)
3. All Frida commands use USB mode by default

Use menu option **[9] Frida Server Config** to switch to a custom host:port (`-H ip:port`), restart the server on a custom listen address, or kill the server.

### Framework Detection

Detection scans (emulator, anti-tamper) automatically identify the app's framework before scanning and adjust keyword groups accordingly.

| Framework | Detection Method | Scan Adjustments |
|-----------|-----------------|------------------|
| **Flutter** | `libflutter.so` in `lib/` (definitive) | Adds Flutter security plugin keywords |
| **React Native** | `libreactnativejni.so`, `libhermes.so`, or `libjsc.so` (definitive) | Adds RN security keywords; scans `.bundle` files |
| **Kotlin** | `kotlin/` directory in smali | Default Java/Kotlin keyword coverage |
| **Java** | Default fallback | Default keyword coverage |

**Native SDK detection** runs on every scan regardless of framework, identifying security SDKs from `.so` files:

| SDK | Signature Files |
|-----|----------------|
| VKey VGuard | `libvguard.so`, `libchecks.so`, `libvosWrapperEx.so` |
| Zimperium | `libzdefend.so`, `libz9.so` |
| Promon SHIELD | `libshield.so` |
| DexGuard | `libdexguard.so` |
| Frida Gadget | `libfrida-gadget.so` |

### Secret Detection (Options 2 & 5)

Both Storage Audit and Security Scan use ~40 regex patterns to detect hardcoded secrets:

| Category | What It Detects |
|----------|----------------|
| **Generic** | Passwords, API keys, tokens, encryption/master keys, JWTs, bearer tokens |
| **AWS** | `AKIA` access key IDs, secret keys, session tokens, S3 bucket URLs |
| **Google / Firebase** | `AIza` API keys, Firebase secrets, OAuth client IDs |
| **Azure** | Storage keys, connection strings, tenant/client secrets |
| **Stripe** | `sk_live_`, `pk_live_`, `rk_live_` keys |
| **Twilio** | `SK` API keys, auth tokens, account SIDs |
| **SendGrid** | `SG.` API keys |
| **Slack** | `xox[bprs]-` tokens, webhook URLs |
| **GitHub** | `ghp_`/`ghs_` PATs, fine-grained tokens |
| **Payment** | PayPal, Braintree, Razorpay secrets |
| **Push / FCM** | FCM/GCM/APNS server keys |
| **OAuth / SSO** | Client IDs/secrets, redirect URIs |
| **Database** | MongoDB/Postgres/MySQL/Redis connection strings with credentials |
| **Crypto** | PEM private keys, certificates |

Option 2 scans **live data on device** (SharedPreferences, SQLite). Option 5 scans **decompiled APK source** (XML, JSON, properties, YAML).

### Decompile Caching

Detection scans decompile the APK once and cache the output in `.apkanalyzer_tmp/`. Subsequent scans on the same app skip decompilation and reuse the cached directory.

### Requirements

- Python 3.6+
- ADB installed and in PATH
- Rooted Android device connected via USB
- `apktool` — [install](https://ibotpeaches.github.io/Apktool/) (required for detection scans)
- Optional: `frida` + `frida-tools` (for Frida CodeShare)

### Usage

```bash
python3 apkanalyzer.py
```

### MASVS-STORAGE Assessment (Option 10)

Two-phase OWASP MASVS-STORAGE L1 compliance assessment combining static and dynamic analysis.

**Phase 1 — Static Analysis** (decompile + keyword scan):

| Test | What It Checks |
|------|---------------|
| STORAGE-2 | Verbose/debug logging in code — Java, Kotlin/Timber, Native C/C++, Flutter/Dart, React Native/JS |
| STORAGE-3 | Third-party SDKs that may receive user data (analytics, crash reporting, ad networks) |
| STORAGE-4 | Backup configuration — `allowBackup`, `fullBackupContent`, `dataExtractionRules`, custom `BackupAgent` |
| STORAGE-5 | Keyboard cache — `textPassword`/`textNoSuggestions` input type usage |
| STORAGE-6 | Clipboard exposure — `ClipboardManager` usage and `FLAG_SENSITIVE` protection |
| STORAGE-7 | WebView data storage settings and cache clearing |
| STORAGE-8 | Screenshot protection — `FLAG_SECURE` usage |
| STORAGE-9 | External storage API usage and scoped storage adoption |
| STORAGE-10 | Notification data exposure — `VISIBILITY_PRIVATE`/`VISIBILITY_SECRET` |

**Phase 2 — Dynamic Analysis** (launch app + live monitoring):

The tool clears logcat, launches the app, and starts background logcat capture. After user interaction:

| Test | What It Checks |
|------|---------------|
| STORAGE-1 | SharedPreferences and SQLite databases scanned for plaintext secrets, tokens, JWTs (post-interaction) |
| STORAGE-2 | Captured logcat analyzed for leaked sensitive data matching secret patterns |
| STORAGE-7 | WebView cache size on device |
| STORAGE-9 | External storage data size on device |

Results are categorized as PASS/FAIL/WARN with a compliance verdict: **COMPLIANT**, **PARTIALLY COMPLIANT**, or **NON-COMPLIANT**.

### Testcases for Fun (Option 11)

Interactive sub-menu with 5 test cases for hands-on exploration of app attack surface.

| Test | What It Does |
|------|-------------|
| **Launch Exported Activities** | Parses manifest for `android:exported="true"` activities, then `am start -n` each one. Successful launches may indicate auth bypass. |
| **Launch Exported Services** | Same for exported services via `am startservice -n`. |
| **Launch Broadcast Receivers** | Sends empty broadcast to each exported receiver via `am broadcast -n` and shows responses. |
| **Clipboard Spy** | Prompts user to copy sensitive data in the app, then reads clipboard via `service call clipboard` / `dumpsys clipboard`. Reports if sensitive data is accessible. |
| **Dev/Staging URL Finder** | Decompiles APK and scans all files for `dev.`, `staging.`, `test.`, `localhost`, `127.0.0.1`, `10.0.2.2`, private IPs (192.168.x.x, 10.x.x.x, 172.16-31.x.x), and `uat.`/`qa.` subdomains. |

### Frida CodeShare Scripts (Option 8)

38 pre-configured CodeShare scripts organized by category. Plus custom CodeShare URL support.

| Group | Scripts | What They Do |
|-------|---------|-------------|
| **SSL Pinning Bypass** | Multi-Unpinning, Universal Android, Universal v2, Flutter TLS, OkHttp4 | Bypass SSL certificate pinning across frameworks |
| **Root Detection Bypass** | fridantiroot, Multi-Library, RootBeer, Xamarin, freeRASP (RN), Talsec (Flutter) | Hide root from various detection libraries |
| **Anti-Debug / Anti-Tamper** | Anti-Debug, USB Debug Detection, Developer Mode, Anti-Frida | Bypass debugger/developer/Frida detection |
| **Multi-Bypass (All-in-One)** | SSL+Root+Emulator, Root+Emulator+SSL, OneRule | Combined bypass scripts |
| **Biometric / Auth** | Universal Biometric, Android 11+ Biometric | Bypass fingerprint/biometric prompts |
| **Monitoring — Network** | Traffic Interceptor, OkHttp3 Interceptor, TCP Trace | Intercept and log network activity |
| **Monitoring — Crypto** | Crypto Monitor, AES Monitor, KeyStore Extractor | Monitor crypto operations, extract keys |
| **Monitoring — Storage** | SharedPrefs, EncryptedSharedPrefs, SQLite, File System, Clipboard | Monitor data storage read/write |
| **Monitoring — Intents / WebView** | Intent Intercept, Deep Link Observer, WebView Debugger | Log intents, deep links, enable WebView debug |
| **Tracing / Enumeration** | raptor Tracer, JNI Trace, List Classes, DEX Dump | Trace method calls, enumerate classes, dump packed DEX |

---

## How It Works

- All commands run via `adb shell su -c` for root access
- Target app selected once at startup (`pm list packages -3`), reused across all features
- Press `[a]` from the main menu to switch target app at any time
- No external Python dependencies — pure stdlib
- Extracted APKs saved to `./extracted_apks/`
- Screenshots saved to `./screenshots/`
- Decompiled cache saved to `./.apkanalyzer_tmp/`
