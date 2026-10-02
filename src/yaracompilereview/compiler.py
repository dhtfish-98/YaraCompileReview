# New implementation author: dhtfish98.
"""Private compiler subprocess. Never calls Rules.match or reads include files."""

import json
import re
import sys


def native_version_supported(version):
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", version):
        return False
    return tuple(map(int, version.split("."))) >= (4, 5, 8)


def main():
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
        if sys.platform.startswith("linux"):
            resource.setrlimit(
                resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024)
            )
    except (ImportError, ValueError, OSError):
        print(
            json.dumps(
                {
                    "status": "OPEN",
                    "complete": False,
                    "findings": ["compiler_resource_controls_unavailable"],
                }
            )
        )
        return 0
    try:
        import yara
    except ImportError:
        print(
            json.dumps(
                {
                    "status": "OPEN",
                    "complete": False,
                    "findings": ["yara_compiler_dependency_missing"],
                }
            )
        )
        return 0
    native_version = getattr(yara, "YARA_VERSION", None)
    if not native_version_supported(native_version):
        print(json.dumps({
            "status": "OPEN", "complete": False,
            "findings": ["native_yara_version_unsupported_or_before_4_5_8"],
            "compiler_version": native_version if isinstance(native_version, str) else None,
        }))
        return 0
    try:
        maximum = 6 * 4 * 1024 * 1024 + 65536
        transport = sys.stdin.buffer.read(maximum + 1)
        if len(transport) > maximum:
            print(
                json.dumps(
                    {
                        "status": "FAIL",
                        "complete": False,
                        "findings": ["serialized_source_limit"],
                    }
                )
            )
            return 0
        doc = json.loads(transport)
        includes = doc["includes"]

        def callback(name, filename, namespace):
            if name not in includes:
                raise ValueError("include_not_authorized")
            return includes[name]

        compiled = yara.compile(
            sources=doc["sources"],
            includes=bool(includes),
            include_callback=callback,
            error_on_warning=True,
        )
        count = sum(1 for _ in compiled)
        result = {
            "status": "PASS",
            "complete": True,
            "findings": [],
            "compiled_rule_count": count,
            "compiler_version": native_version,
        }
    except (yara.Error, ValueError, KeyError, RecursionError):
        result = {
            "status": "FAIL",
            "complete": False,
            "findings": ["rule_compile_error_or_warning_or_unauthorized_include"],
        }
    result["compiler_version"] = native_version
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
