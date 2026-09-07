# APK Analyzer

Android application analysis for local APKs and connected devices. Supports Windows, Linux, WSL, and macOS, with no third-party Python packages required for the core application.

[Download](https://github.com/worldtreeboy/apkAnalyzer/releases/latest) · [Release notes](https://github.com/worldtreeboy/apkAnalyzer/releases) · [Issues](https://github.com/worldtreeboy/apkAnalyzer/issues)

## Features

- **Static analysis:** manifest configuration, permissions, exported components, network policies, signing, code patterns, and hardcoded secrets.
- **APK formats:** `.apk`, `.apks`, `.aab`, and directories containing split APKs.
- **Device tools:** storage audits, runtime checks, logcat, screenshots, Frida integration, and APK patching.
- **Reports:** JSON, HTML, and SARIF, with severity, confidence, source locations where available, and coverage details.

## Requirements

| Workflow | Requirements |
| --- | --- |
| Local static scan | Python 3.8+, Java, and apktool |
| Signing verification | apksigner; missing signing evidence makes coverage incomplete |
| App Bundle (`.aab`) | Java and bundletool |
| Connected device | ADB; root or Frida for selected features |

Local scans do not require ADB or a connected device. App Bundle scans may have incomplete coverage for dynamic-feature modules.

## Quick start

Clone the repository or extract the complete [release ZIP](https://github.com/worldtreeboy/apkAnalyzer/releases/latest). Keep `apkAnalyzer.py` beside the included `apk_analyzer/` directory.

```bash
git clone https://github.com/worldtreeboy/apkAnalyzer.git
cd apkAnalyzer
python3 apkAnalyzer.py scan --apk app.apk --format json --output report.json
```

Use `--format html` or `--format sarif` for other report formats. For `.aab` input, add `--bundletool /path/to/bundletool.jar`. Omitting `--output` creates a timestamped report.

### CI

```bash
python3 apkAnalyzer.py scan --apk app.apk --format sarif --output report.sarif --fail-on high
```

`--fail-on` accepts `critical`, `high` (default), `medium`, `low`, `info`, or `none`.

| Exit code | Meaning |
| --- | --- |
| `0` | Scan completed; no findings met the threshold |
| `1` | Scan completed; findings met the threshold |
| `2` | Scan failed or required evidence was incomplete |

`INCONCLUSIVE` identifies missing or incomplete evidence and takes precedence over finding thresholds. A completed scan does not establish that an application is vulnerability-free.

### Device mode

Enable USB debugging, connect the device, then run:

```bash
python3 apkAnalyzer.py
```

Select an app and a tool from the menu. Use `[r]` to export JSON or HTML reports. For command options, run `python3 apkAnalyzer.py scan --help`.

## Development

The launcher is `apkAnalyzer.py`; reusable modules live in `apk_analyzer/`. Run the regression suite without a connected device:

```bash
python3 -m unittest discover -s tests -q
```

Licensed under the [MIT License](LICENSE).
