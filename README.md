<div align="center">

# APK Analyzer

### Know what ships inside your APK.

Find risky Android settings, trace the evidence, and turn an app package into a report your team can act on.

[![Download latest release](https://img.shields.io/badge/Download-latest_release-2ea44f?style=for-the-badge)](https://github.com/worldtreeboy/apkAnalyzer/releases/latest)
[![Star on GitHub](https://img.shields.io/badge/Star_on_GitHub-facc15?style=for-the-badge&logo=github&logoColor=black)](https://github.com/worldtreeboy/apkAnalyzer)

[![CI](https://github.com/worldtreeboy/apkAnalyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/worldtreeboy/apkAnalyzer/actions/workflows/ci.yml)
![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)
[![MIT License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

Windows · Linux · WSL · macOS

</div>

APK Analyzer is a Python CLI for reviewing Android packages and installed apps. Run it headlessly for repeatable local or CI scans, or connect an Android device for interactive analysis and runtime checks.

Each reported issue includes severity, confidence, remediation guidance, MASVS/CWE references, and source locations where the evidence allows it. When required evidence is unavailable, APK Analyzer says `INCONCLUSIVE` instead of quietly reporting a clean result.

## What it gives you

- **Useful findings, not a wall of matches.** Results are grouped by risk and include the context needed to verify and fix them.
- **Reports for people and pipelines.** Export HTML for review, JSON for automation, or SARIF for code-scanning systems.
- **Local scans without a phone.** Analyze `.apk`, `.apks`, `.aab`, and split-APK directories from the command line.
- **A deeper device workflow.** Inspect app storage, runtime behavior, logs, screenshots, and optional Frida-assisted tests from one interactive menu.
- **Fail-safe coverage.** Missing tools, unreadable inputs, truncated scans, and incomplete evidence remain visible in the final result.

## What APK Analyzer looks for

| Area | Examples |
| --- | --- |
| Manifest and platform | Debuggable builds, backup rules, dangerous permissions compared with code, exported components, deep links, Play target SDK, task affinity, and signing schemes |
| Network and WebView | Cleartext traffic, Network Security Config, JavaScript bridges, file access, universal file access, WebView debugging, and mixed content |
| Code and IPC | PendingIntent mutability, per-call broadcast protection, debug and verbose logging, and framework indicators |
| Data exposure | Hardcoded secrets scored by key shape, clipboard use, keyboard caching, screenshots, and WebView cache |
| UI resilience | Tapjacking signals and missing sensitive-screen protections |
| Connected device | App storage, file permissions, runtime secrets, exported-component behavior, logcat leakage, and device metadata |

Findings use OWASP MASVS categories and CWE references where a reliable mapping exists. Static checks read the decoded manifest, resources, smali, and native-library indicators from the base package and from every feature split that parsed. A split that cannot be read does not become a pass.

## How a result is decided

The scanner reports evidence it can prove. These rules are the ones that most often change a result:

- **Permissions versus code.** A dangerous permission with no mapped platform API is a finding only when the smali and XML were fully scanned. A mapped API whose permission is missing from the merged manifest is a finding only when every feature-split manifest was read. If a split could not be merged, that case stays `INCONCLUSIVE` instead of being called a missing permission. A permission found in a split that did parse counts as declared.
- **WebView.** `addJavascriptInterface` is its own finding. File access, universal file access, debugging, and mixed content are scored from the individual call. A proven disabled value, including mixed content `NEVER_ALLOW`, is not a finding. A non-constant argument is not scored.
- **Broadcasts and logs.** Each `sendBroadcast` or `sendBroadcastAsUser`, and each debug or verbose log call, is counted on its own. A permission-protected send does not cover an unprotected send in the same file. Local broadcasts are ignored.
- **Backups.** `allowBackup="true"` stays high when backup rules are missing, unreadable, or still include private files. Readable `fullBackupContent` and `dataExtractionRules` can lower the finding when they exclude the domains that apply to the app's SDK range. A referenced rules file that cannot be read stays high and `INCONCLUSIVE`.
- **Secrets.** Live key shapes stay critical. A generic assignment such as `password=` or `api_key=` is medium severity and medium confidence. Public identifiers such as Firebase `AIza`, Twilio `SK`/`AC`, and AWS `AKIA` are not reported. Matches under common SDK paths are labeled rather than hidden, and a live key in those paths is still critical.
- **Target SDK.** New Play updates are checked against API 36. A target below API 35 is also below the existing-app visibility floor. The SDK of a connected phone is not used as the bar.

## One scanner, two workflows

### Local and CI scans

Use the `scan` command when you already have an APK or bundle. This workflow requires no connected device and normally writes a report even when setup or runtime errors make coverage incomplete.

```bash
python3 apkAnalyzer.py scan --apk app.apk --format html --output report.html
```

Use `python` or `py` instead of `python3` on Windows if that is your Python command.

### Connected-device analysis

Connect a device with USB debugging enabled and launch the interactive interface:

```bash
python3 apkAnalyzer.py
```

The device workflow needs `adb`. Root and Frida are optional, and the menu says when a check cannot run without them.

| Key | Action |
| --- | --- |
| `1` | App analysis |
| `2` | Storage audit |
| `3` | Shell |
| `4` | Screenshot |
| `5` | Security scan |
| `6` | LokiBoard keyboard-cache check |
| `7` | Live logcat |
| `8` | Frida CodeShare |
| `9` | Binary patcher (Frida Gadget or LSPatch) |
| `10` | Frida server setup |
| `11` | Exported-component, clipboard, and URL probes |
| `12` | Runtime checks over ADB |
| `a` | Switch the selected app |
| `r` | Export the session report as JSON or HTML |

Gadget and LSPatch patching apply to a single APK. A split install is refused. Runtime checks can launch the selected app. Storage, clipboard, and cache checks stay `INCONCLUSIVE` without root.

## Quick start

Download and extract the [latest release](https://github.com/worldtreeboy/apkAnalyzer/releases/latest), or clone the repository:

```bash
git clone https://github.com/worldtreeboy/apkAnalyzer.git
cd apkAnalyzer
```

Run `apkAnalyzer.py`. Keep it beside the `apk_analyzer/` package, which is the library the launcher imports, not a second program. No third-party Python packages are required for the core scanner.

Generate an HTML report:

```bash
python3 apkAnalyzer.py scan --apk path/to/app.apk --format html --output report.html
```

Generate JSON for scripts:

```bash
python3 apkAnalyzer.py scan --apk app.apk --format json --output report.json
```

If `--output` is omitted, APK Analyzer writes a timestamped report in the current directory.

## Supported inputs

| Input | How it is handled |
| --- | --- |
| `.apk` | Decoded and scanned as one Android package |
| `.apks` | Safely extracted, with the base APK and contained splits analyzed together |
| Split-APK directory | A base APK is selected and sibling splits are included in coverage |
| `.aab` | Converted with bundletool, then analyzed as an APK set |

For App Bundles, provide bundletool as a native executable or JAR:

```bash
python3 apkAnalyzer.py scan --apk app.aab --bundletool /path/to/bundletool.jar --format html --output report.html
```

Universal APK output can omit non-fused, on-demand dynamic features. APK Analyzer records that limitation as incomplete coverage rather than assuming those modules were inspected. Feature-split manifests are merged with the base. If one cannot be parsed, checks that depend on a permission or component being absent stay `INCONCLUSIVE`. For split inputs and APKs generated from an AAB, signing checks do not prove the complete source or app-store signing chain and are also marked incomplete.

## Requirements

| Tool | Needed for |
| --- | --- |
| Python 3.8+ | All modes |
| [apktool](https://apktool.org/docs/install/) | Decoding packages for static analysis |
| Java | Running apktool or bundletool when supplied as JARs |
| `apksigner` | Signing-scheme verification for a single APK |
| [bundletool](https://developer.android.com/tools/bundletool) | `.aab` input |
| Android SDK Platform Tools (`adb`) | Connected-device mode |
| Root and Frida | Optional runtime features |

Add the tools you use to `PATH`. On Windows, apktool and apksigner are started with `java -jar` when a JAR is beside the tool. `.bat` and `.cmd` wrappers are not launched. When a selected check requires a missing dependency, its evidence is reported as unavailable instead of a pass. Frida features also require `frida-tools` and a compatible `frida-server` on the device.

## Reports and CI

Choose a format based on where the result is going:

- **HTML** gives reviewers a readable, shareable report.
- **JSON** preserves structured findings, summary counts, locations, and coverage metadata.
- **SARIF 2.1.0** integrates with code-scanning platforms and CI systems.

The headless scanner defaults to JSON output and a `high` failure threshold.

Fail a pipeline when a finding reaches a chosen severity:

```bash
python3 apkAnalyzer.py scan --apk app.apk --format sarif --output report.sarif --fail-on high
```

| Exit code | Meaning |
| --- | --- |
| `0` | The scan completed and no finding met the selected threshold |
| `1` | At least one finding met the selected threshold |
| `2` | The scan failed or required evidence was incomplete |

Incomplete coverage takes precedence over the finding threshold so a partial scan cannot silently pass CI. Use `--fail-on none` when you want a report without finding-based failure while still preserving exit code `2` for incomplete analysis.

See every command-line option with:

```bash
python3 apkAnalyzer.py scan --help
```

## Output locations

- Headless reports are written to `--output`, or to a timestamped file in the current directory.
- Interactive APK extraction uses `extracted_apks/`.
- Screenshots are saved as timestamped PNG files under `screenshots/`.
- Temporary local-scan decompilation is removed after the scan completes.

## Reading the result

APK Analyzer distinguishes three outcomes:

- A **finding** means the scanner observed evidence that matches a defined rule.
- A **pass** means that check completed without finding the tested condition.
- **`INCONCLUSIVE`** means the scanner could not prove coverage, usually because evidence, tooling, or part of the input was unavailable.

Static matches can require manual verification, and connected-device checks may launch or stop the selected app. Split variants are analyzed together where their individual runtime semantics cannot be proven. Static and runtime results provide evidence for review; they do not prove that an application is vulnerability-free.

## Development

Run the test suite with the Python standard library:

```bash
python3 -m unittest discover -s tests -q
```

Bug reports and focused pull requests are welcome. Please include the operating system, Python version, input type, command used, and sanitized error output so an issue can be reproduced.

Use APK Analyzer only on applications and devices you own or are authorized to test.

---

**Saved you time? [Give APK Analyzer a star ⭐](https://github.com/worldtreeboy/apkAnalyzer).** It helps more Android developers and security testers discover the project.

[Report a bug](https://github.com/worldtreeboy/apkAnalyzer/issues) · [Release notes](https://github.com/worldtreeboy/apkAnalyzer/releases) · [Contribute a fix](https://github.com/worldtreeboy/apkAnalyzer/pulls)
