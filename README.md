<div align="center">

# APK Analyzer

### Know what ships inside your APK.

A static scan of the package, and a dynamic scan on a connected device.

[![Download latest release](https://img.shields.io/badge/Download-latest_release-2ea44f?style=for-the-badge)](https://github.com/worldtreeboy/apkAnalyzer/releases/latest)
[![Star on GitHub](https://img.shields.io/badge/Star_on_GitHub-facc15?style=for-the-badge&logo=github&logoColor=black)](https://github.com/worldtreeboy/apkAnalyzer)

[![CI](https://github.com/worldtreeboy/apkAnalyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/worldtreeboy/apkAnalyzer/actions/workflows/ci.yml)
![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)
[![MIT License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

Windows · Linux · WSL · macOS

</div>

APK Analyzer reviews `.apk`, `.apks`, `.aab`, and split-APK directories. `scan` is static and does not use a device. The dynamic scan is menu `12`: it launches the installed app over `adb`. Each finding has severity, confidence, remediation, and a MASVS or CWE reference. Missing evidence is `INCONCLUSIVE`, not a pass.

No third-party Python packages. Run `apkAnalyzer.py` and keep it next to `apk_analyzer/`.

## Quick start

[Download the latest release](https://github.com/worldtreeboy/apkAnalyzer/releases/latest) and extract it, or clone the repo. You need Python 3.8+ and [apktool](https://apktool.org/docs/install/).

```bash
python3 apkAnalyzer.py scan --apk app.apk --format html --output report.html
```

On Windows, use `python` if `python3` is not the command. Omit `--output` to write a timestamped file in the current directory.

| Goal | Command |
| --- | --- |
| JSON | `python3 apkAnalyzer.py scan --apk app.apk --format json --output report.json` |
| CI | `python3 apkAnalyzer.py scan --apk app.apk --format sarif --output report.sarif --fail-on high` |
| App Bundle | `python3 apkAnalyzer.py scan --apk app.aab --bundletool /path/to/bundletool.jar --format html --output report.html` |
| Dynamic scan | `python3 apkAnalyzer.py`, then `12` |

Exit codes below are for `scan` only. The dynamic scan is interactive and does not use them.

| Exit code | Meaning |
| --- | --- |
| `0` | Finished, and nothing met `--fail-on` (default `high`) |
| `1` | A finding met the threshold |
| `2` | The scan failed, or coverage was incomplete |

Exit code `2` wins over a clean finding count, so a partial scan cannot pass CI. `--fail-on` accepts `critical`, `high`, `medium`, `low`, `info`, and `none`.

## What it checks

| Area | Examples |
| --- | --- |
| Manifest | Debuggable, backup rules, exported components, deep links, task hijacking, Play target SDK, signing |
| Permissions | Dangerous permissions with no mapped API, and mapped APIs with no declared permission |
| WebView | JavaScript bridge, file access, debugging, mixed content |
| Code | PendingIntent flags, unprotected broadcasts, debug logging |
| Data | Live secrets versus generic assignments, clipboard, keyboard cache, screenshots |
| Dynamic scan | After launch: private storage, world-readable files, exported activities, clipboard, logcat, WebView cache |

A few rules that change the result:

- Permissions are compared with smali and XML only after that code, and every feature-split manifest, was actually read.
- WebView, broadcasts, and log calls are scored per call. One safe call does not cover another.
- `allowBackup="true"` stays serious unless the backup rules for that SDK range exclude private data.
- Live keys stay critical. `api_key=` style hits are medium. Public IDs such as Firebase `AIza`, Twilio `SK`/`AC`, and AWS `AKIA` are ignored.
- New Play updates are checked against API 36. Below API 35 is also below the existing-app floor. A connected phone does not set the bar.

Results are evidence for review. They do not prove an app is safe.

## On a device

Connect a phone with USB debugging and `adb` on `PATH`.

| Key | Action | Key | Action |
| --- | --- | --- | --- |
| `1` | App analysis | `7` | Logcat |
| `2` | Storage audit | `8` | Frida CodeShare |
| `3` | Shell | `9` | Gadget or LSPatch patcher |
| `4` | Screenshot | `10` | Frida server |
| `5` | Security scan | `11` | Component, clipboard, and URL probes |
| `6` | Keyboard cache | `12` | Dynamic scan |
| `a` | Switch app | `r` | Export JSON or HTML |

Menu `12` is the dynamic scan. It launches the selected app, checks private storage, world-readable files, exported activities, the clipboard, logcat, and the WebView cache, then force-stops the app. Storage, file permissions, clipboard, and WebView cache need root and stay inconclusive without it. Logcat and exported activities do not. Patching applies to a single APK, not a split install.

## Requirements

| Tool | Required for |
| --- | --- |
| Python 3.8+ | Everything |
| [apktool](https://apktool.org/docs/install/) and Java | Decoding packages |
| `apksigner` | Signing check on a single APK |
| [bundletool](https://developer.android.com/tools/bundletool) | `.aab` input |
| `adb` | Dynamic scan and the device menu |
| Root | Storage, file permissions, clipboard, and WebView cache in the dynamic scan |
| `frida-tools`, `frida-server` | Optional hooking. Not required for the dynamic scan |

Put the tools you use on `PATH`. On Windows, a nearby `.jar` is launched with `java -jar`. `.bat` and `.cmd` wrappers are not. A missing tool makes that check inconclusive.

Screenshots go to `screenshots/`. Extracted APKs go to `extracted_apks/`. Temporary decompilation from a local scan is deleted when the scan finishes.

## Development

```bash
python3 -m unittest discover -s tests -q
```

Issues and pull requests are welcome. Include the OS, Python version, input type, command, and a sanitized error. Test only apps and devices you are allowed to test.

[Report a bug](https://github.com/worldtreeboy/apkAnalyzer/issues) · [Release notes](https://github.com/worldtreeboy/apkAnalyzer/releases) · [Contribute](https://github.com/worldtreeboy/apkAnalyzer/pulls)
