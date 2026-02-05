# APK Analyzer

Android security analysis tools powered by ADB with root access.

---

## APK Analyzer

Interactive terminal menu for app analysis, storage auditing, shell access, screenshots, security scanning, and Frida integration.

**Target app is selected once at startup** — all features operate on the selected app. Press `[a]` from the menu to switch to a different app at any time.

### Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | **App Analysis** | View permissions, components, version info, extract APK |
| 2 | **Storage Audit** | Scan app data directories for SharedPreferences secrets, SQLite databases, cache |
| 3 | **Shell Access** | Interactive root shell via `su -c` |
| 4 | **Screenshot** | Capture device screen and save locally |
| 5 | **Security Scan** | Debuggable flag, allowBackup, exported components, dangerous permissions, SDK version, cleartext traffic, network security config, data leakage, deeplinks, WebView JS interface, PendingIntent mutability, implicit broadcast, FLAG_SECURE, clipboard exposure, debug logging, keyboard cache, task hijacking, tapjacking, APK signing scheme |
| 6 | **Keyboard Cache Detection** | Check if LokiBoard keyboard caches user input in plaintext. Prompts user to type in the app, then searches all `lokiboard_files_*.txt` cache files for the entered text |
| 7 | **Logcat Live Monitor** | Stream `adb logcat` in real-time filtered by a search string. Matched text highlighted in bold red. Ctrl+C to stop |
| 8 | **Frida CodeShare** | Auto-start frida-server (USB default), run local bypass scripts or 38 grouped CodeShare scripts (see below) |
| 9 | **Binary Patcher** | Sub-menu: Frida Gadget (inject frida-gadget.so) or LSPatch (embed LSPosed/Xposed framework) — see below |
| 10 | **Frida Server Config** | Switch between USB (`-U`) and custom host:port (`-H ip:port`), restart/kill frida-server, set up ADB port forwarding |
| 11 | **Testcases for Fun** | Launch exported activities/services/receivers with intent-filter actions + custom extras, clipboard spy, dev/staging URL finder (see below) |

### Auto Frida Server

On startup (with root), the analyzer automatically:
1. Kills any existing frida-server process
2. Starts frida-server on default USB port (`-U`)
3. All Frida commands use USB mode by default

Use menu option **[10] Frida Server Config** to switch to a custom host:port (`-H ip:port`), restart the server on a custom listen address, or kill the server.

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

### Security Scan Checks (Option 5)

Static analysis of decompiled APK and AndroidManifest.xml — 19 checks with PASS/FAIL/WARN scoring:

| Check | What It Flags |
|-------|--------------|
| **Debuggable** | `android:debuggable="true"` in manifest |
| **allowBackup** | Backup enabled without `fullBackupContent`/`dataExtractionRules` |
| **Exported Components** | Activities, services, receivers, providers with `exported="true"` |
| **Dangerous Permissions** | `CAMERA`, `LOCATION`, `READ_SMS`, `RECORD_AUDIO`, etc. |
| **SDK Version** | `minSdk` < 23 or `targetSdk` < 30 |
| **Cleartext Traffic** | `usesCleartextTraffic="true"` in manifest |
| **Network Security Config** | Missing or trusts user-installed CAs |
| **Data Leakage** | Hardcoded secrets in XML, JSON, properties, YAML files |
| **Deeplinks** | Custom URI schemes/hosts without proper validation |
| **WebView JS Interface** | `addJavascriptInterface()` usage (XSS risk on SDK < 17) |
| **PendingIntent** | Missing `FLAG_IMMUTABLE`/`FLAG_MUTABLE` (Android 12+ hijacking) |
| **Broadcast Security** | `sendBroadcast()` without permission protection |
| **FLAG_SECURE** | Missing screenshot protection on sensitive screens |
| **Clipboard Exposure** | `ClipboardManager` usage without `FLAG_SENSITIVE` |
| **Debug Logging** | `Log.v`/`Log.d`, `Timber`, `console.log`, `debugPrint` in production code |
| **Keyboard Cache** | Missing `textPassword`/`textNoSuggestions` input types |
| **Task Hijacking** | Activities with custom `taskAffinity` (StrandHogg attack) |
| **Tapjacking** | Missing `filterTouchesWhenObscured` overlay protection |
| **APK Signing Scheme** | v1-only signing vulnerable to Janus (CVE-2017-13156), checks v2/v3/v4 |

### Decompile Caching

Detection scans decompile the APK once and cache the output in `.apkanalyzer_tmp/`. Subsequent scans on the same app skip decompilation and reuse the cached directory.

### Requirements

- Python 3.6+
- ADB installed and in PATH
- Rooted Android device connected via USB
- `apktool` — [install](https://ibotpeaches.github.io/Apktool/) (required for detection scans)
- Optional: `apksigner` from Android SDK build-tools (for APK signing scheme check)
- Optional: `frida` + `frida-tools` (for Frida CodeShare)

### Usage

```bash
python3 apkanalyzer.py
```

### Binary Patcher (Option 9)

Sub-menu with two patching methods for non-rooted devices:

#### [1] Frida Gadget

Patches the selected APK with [Frida Gadget](https://frida.re/docs/gadget/) for dynamic analysis.

**Pipeline:**

| Step | Action |
|------|--------|
| 1 | **Check dependencies** — `apktool` (or `java -jar apktool.jar`), `jarsigner`/`apksigner`, `keytool` |
| 2 | **Download Frida Gadget** — `frida-gadget-17.6.2-android-arm64.so.xz` from GitHub releases (cached in `.gadget_cache/`, skips download if already present) |
| 3 | **Get APK** — uses local copy from `extracted_apks/` or pulls from device |
| 4 | **Decompile** with apktool |
| 5 | **Find launcher activity** from `AndroidManifest.xml` |
| 6 | **Patch manifest** — add `INTERNET` permission, set `extractNativeLibs="true"` |
| 7 | **Inject smali** — `System.loadLibrary("frida-gadget")` into `<clinit>` or `onCreate` |
| 8 | **Copy** `libfrida-gadget.so` into `lib/arm64-v8a/` |
| 9 | **Rebuild** with apktool |
| 10 | **Sign** with auto-generated debug keystore (+ zipalign if available) |

Output saved to `patched_apks/<pkg>_gadget_patched.apk`.

#### [2] LSPatch

Patches the selected APK with [LSPatch](https://github.com/LSPosed/LSPatch) to embed the LSPosed/Xposed framework — load Xposed modules without root.

**Pipeline:**

| Step | Action |
|------|--------|
| 1 | **Check dependency** — `java` (JDK/JRE) |
| 2 | **Download LSPatch jar** — `jar-v0.6-398-release.jar` from GitHub releases (cached in `.gadget_cache/`) |
| 3 | **Get APK** — uses local copy from `extracted_apks/` or pulls from device |
| 4 | **Run LSPatch** — `java -jar lspatch.jar <apk> -d -v -l 2 -o patched_apks/` |

Flags: `-d` (debuggable), `-v` (verbose), `-l 2` (signature bypass level 2).

Output saved to `patched_apks/`.

### Testcases for Fun (Option 11)

Interactive sub-menu with 5 test cases for hands-on exploration of app attack surface.

| Test | What It Does |
|------|-------------|
| **Launch Exported Activities** | Parses manifest for `android:exported="true"` activities, shows intent-filter actions, lets you select individual components or launch all. Auto-includes `-a action` from intent-filters. Supports custom extras (e.g. `--es key value --ei num 42`). |
| **Launch Exported Services** | Same for exported services via `am startservice`, with action and extras support. |
| **Launch Broadcast Receivers** | Same for exported receivers via `am broadcast`, with action and extras support. |
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
- Patched APKs saved to `./patched_apks/`
- Screenshots saved to `./screenshots/`
- Frida Gadget & LSPatch jar cached in `./.gadget_cache/`
- Decompiled cache saved to `./.apkanalyzer_tmp/`
