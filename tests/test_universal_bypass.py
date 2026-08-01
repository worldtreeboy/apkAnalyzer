import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "frida_scripts" / "universal_bypass.js"


class UniversalBypassTests(unittest.TestCase):
    def test_script_is_valid_utf8_and_has_no_target_specific_patches(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('const VERSION = "2.0.0"', source)
        self.assertIn("Module.findGlobalExportByName", source)
        self.assertIn("Process.attachModuleObserver", source)
        for obsolete in (
            "CRASH_OFFSET",
            "libvosWrapperEx",
            "Memory.patchCode",
            "ARM64_RET",
            "Interceptor.replace(pAbort",
        ):
            self.assertNotIn(obsolete, source)

    def test_javascript_syntax(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js is unavailable")
        result = subprocess.run(
            [node, "--check", str(SCRIPT)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
