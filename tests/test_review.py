import json, unittest
from yaracompilereview import inspect


def mapping(source, includes):
    return json.dumps(
        {
            "format": "yara-local-compile-v1",
            "sources": {"main": source},
            "includes": includes,
        }
    ).encode()


class Tests(unittest.TestCase):
    def test_valid(self):
        r = inspect(b"rule Synthetic { condition: true }")
        self.assertEqual(r["status"], "PASS")
        self.assertEqual(r["compiled_rule_count"], 1)

    def test_multiple(self):
        self.assertEqual(
            inspect(b"rule A {condition: true} rule B {condition: A}")[
                "compiled_rule_count"
            ],
            2,
        )

    def test_invalid(self):
        self.assertEqual(inspect(b"rule broken { condition: ( }")["status"], "FAIL")

    def test_fs_include(self):
        self.assertEqual(
            inspect(b'include "/etc/passwd" rule A {condition:true}')["status"], "FAIL"
        )

    def test_authorized_include(self):
        self.assertEqual(
            inspect(
                mapping(
                    'include "dep.yar" rule A {condition:B}',
                    {"dep.yar": "rule B {condition:true}"},
                )
            )["status"],
            "PASS",
        )

    def test_missing_include(self):
        self.assertEqual(
            inspect(
                mapping('include "absent.yar"', {"dep.yar": "rule B {condition:true}"})
            )["status"],
            "FAIL",
        )

    def test_unsafe_mapping(self):
        self.assertEqual(
            inspect(
                mapping(
                    "rule A {condition:true}", {"../private": "rule B {condition:true}"}
                )
            )["status"],
            "FAIL",
        )

    def test_cycle(self):
        self.assertEqual(
            inspect(mapping('include "a.yar"', {"a.yar": 'include "a.yar"'}))["status"],
            "FAIL",
        )

    def test_size(self):
        self.assertEqual(inspect(b"x" * (2 * 1024 * 1024 + 1))["status"], "FAIL")

    def test_private(self):
        self.assertNotIn(
            "private_literal",
            str(inspect(b'rule A {strings:$a="private_literal" condition: ( }')),
        )

    def test_unknown(self):
        self.assertEqual(inspect(b'{"format":"future"}')["status"], "OPEN")

    def test_lone_surrogates(self):
        for field in ("sources", "includes"):
            d = {
                "format": "yara-local-compile-v1",
                "sources": {"main": "rule A { condition: true }"},
                "includes": {},
            }
            d[field]["x"] = "\ud800"
            self.assertEqual(inspect(json.dumps(d).encode())["status"], "FAIL")

    def test_nonfinite_json(self):
        self.assertEqual(
            inspect(b'{"format":"yara-local-compile-v1","sources":{"main":NaN}}')[
                "status"
            ],
            "FAIL",
        )

    def test_compiler_timeout_is_open(self):
        from unittest.mock import patch
        import subprocess

        with patch(
            "yaracompilereview.core.subprocess.run",
            side_effect=subprocess.TimeoutExpired("compiler", 5),
        ):
            r = inspect(b"rule A { condition:true }")
            self.assertEqual(r["status"], "OPEN")
            self.assertFalse(r["complete"])

    def test_escaped_transport_over_4mib_compiles(self):
        source_a = "//" + "\\" * 1100000 + "\nrule A { condition: true }"
        source_b = "//" + "\\" * 1100000 + "\nrule B { condition: true }"
        raw = json.dumps(
            {
                "format": "yara-local-compile-v1",
                "sources": {"a": source_a, "b": source_b},
            }
        ).encode()
        self.assertGreater(len(raw), 4 * 1024 * 1024)
        r = inspect(raw)
        self.assertEqual(r["status"], "PASS")
        self.assertEqual(r["compiled_rule_count"], 2)
