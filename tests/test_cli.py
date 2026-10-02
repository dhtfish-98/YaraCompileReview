import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "yaracompilereview"


class CliTests(unittest.TestCase):
    def run_cli(self, path):
        return subprocess.run(
            [sys.executable, "-m", PACKAGE, str(path)],
            capture_output=True,
            text=True,
            timeout=12,
        )

    def test_good_and_input_preserved(self):
        path = ROOT / "examples/valid.bin"
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        r = self.run_cli(path)
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["input_sha256"], before)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)

    def test_invalid_input(self):
        r = self.run_cli(ROOT / "examples/invalid.bin")
        self.assertEqual(r.returncode, 1, r.stderr + r.stdout)
        self.assertEqual(json.loads(r.stdout)["status"], "FAIL")
        self.assertNotIn("Traceback", r.stderr)

    def test_read_error_private(self):
        r = self.run_cli(ROOT / "examples/nonexistent_private_path")
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("nonexistent_private_path", r.stdout + r.stderr)

    def test_no_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            link = Path(d) / "alias"
            link.symlink_to(ROOT / "examples/valid.bin")
            r = self.run_cli(link)
            self.assertEqual(r.returncode, 1)

    def test_unsupported_input(self):
        r = self.run_cli(ROOT / "examples/unsupported.bin")
        self.assertEqual(r.returncode, 2, r.stderr + r.stdout)
        self.assertEqual(json.loads(r.stdout)["status"], "OPEN")

    def test_lone_surrogate_cli(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "surrogate.json"
            p.write_bytes(
                b'{"format":"yara-local-compile-v1","sources":{"main":"\\ud800"}}'
            )
            r = self.run_cli(p)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertNotIn("Traceback", r.stderr)

    def test_missing_safe_read_flags_never_open(self):
        import importlib
        from unittest.mock import patch

        core = importlib.import_module(PACKAGE + ".core")
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "link"
            link.symlink_to(ROOT / "examples/valid.bin")
            for flag in ("O_NOFOLLOW", "O_NONBLOCK"):
                for path in (ROOT / "examples/valid.bin", link):
                    with patch.object(core.os, flag, None), patch.object(core.os, "open") as opener:
                        with self.assertRaises(core.Unsupported):
                            core.read_local(path)
                        opener.assert_not_called()

    def test_missing_safe_read_flags_cli_open(self):
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "link"
            link.symlink_to(ROOT / "examples/valid.bin")
            for flag in ("O_NOFOLLOW", "O_NONBLOCK"):
                code = "import os; delattr(os, '" + flag + "'); from " + PACKAGE + ".core import main; raise SystemExit(main())"
                for path in (ROOT / "examples/valid.bin", link):
                    result = subprocess.run([sys.executable, "-c", code, str(path)], capture_output=True, text=True, timeout=12)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    report = json.loads(result.stdout)
                    self.assertEqual(report["status"], "OPEN")
                    self.assertFalse(report["complete"])
                    self.assertEqual(report["findings"], ["safe_local_read_flags_unavailable"])
                    self.assertNotIn("Traceback", result.stderr)


    def test_installed_compiler_excludes_caller_shadow(self):
        import os

        installed_cli = Path(sys.executable).parent / PACKAGE
        self.assertTrue(installed_cli.is_file(), "install the package before running these tests")
        with tempfile.TemporaryDirectory() as directory:
            cwd = Path(directory)
            shadow = cwd / PACKAGE
            shadow.mkdir()
            (shadow / "__init__.py").write_text("from pkgutil import extend_path\n__path__ = extend_path(__path__, __name__)\n")
            (shadow / "compiler.py").write_text('print(\'{"status":"PASS","complete":true,"findings":[],"compiled_rule_count":777}\')\n')
            invalid = cwd / "invalid.yar"
            invalid.write_text("rule invalid { condition: }")
            env = dict(os.environ, PYTHONPATH=str(cwd))
            result = subprocess.run([str(installed_cli), str(invalid)], cwd=cwd, env=env, capture_output=True, text=True, timeout=12)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "FAIL")
        self.assertNotEqual(report.get("compiled_rule_count"), 777)
        self.assertNotIn("Traceback", result.stderr)

    def test_fixed_native_overflow_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "boundary.yar"
            for expression, expected in ((r"~9223372036854775807 * 9223372036854775807", 1), (r"~9223372036854775807 \ -1", 1), (r"-(~9223372036854775807)", 0)):
                path.write_text("rule boundary { condition: (" + expression + ") != 0 }")
                result = self.run_cli(path)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                self.assertEqual(json.loads(result.stdout)["compiler_version"], "4.5.8")
