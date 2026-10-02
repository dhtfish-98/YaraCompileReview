import argparse
import hashlib
import json
import os
import stat
import struct

MAX_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 100000


class Invalid(ValueError):
    pass


class Unsupported(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise Invalid(code)


def unpack(fmt, data, offset=0):
    require(
        offset >= 0 and offset + struct.calcsize(fmt) <= len(data), "truncated_field"
    )
    return struct.unpack_from(fmt, data, offset)


def text(data, encoding="utf-8"):
    try:
        return data.decode(encoding)
    except UnicodeError:
        raise Invalid("invalid_text_encoding") from None


def inspect(data):
    if not isinstance(data, bytes):
        raise TypeError("input must be bytes")
    digest = hashlib.sha256(data).hexdigest()
    try:
        require(len(data) <= MAX_BYTES, "input_limit")
        result = analyze(data)
        result.setdefault("status", "PASS")
        result.setdefault("complete", result["status"] == "PASS")
        result.setdefault("findings", [])
    except Unsupported as exc:
        result = {"status": "OPEN", "complete": False, "findings": [str(exc)]}
    except Invalid as exc:
        result = {"status": "FAIL", "complete": False, "findings": [str(exc)]}
    result.update(
        {
            "input_sha256": digest,
            "input_bytes": len(data),
            "claim": "Recorded format checks only; no authenticity, runtime or CVP approval conclusion.",
        }
    )
    return result


def read_local(path):
    fd = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode), "regular_file_required")
        require(info.st_size <= MAX_BYTES, "input_limit")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(MAX_BYTES + 1)
        require(len(data) <= MAX_BYTES, "input_limit")
        after = os.fstat(fd)
        require(
            (info.st_size, info.st_mtime_ns, info.st_ino)
            == (after.st_size, after.st_mtime_ns, after.st_ino),
            "input_changed_during_read",
        )
        return data
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(
        description="Read an explicitly supplied local evidence file and print a private-safe JSON report."
    )
    parser.add_argument("input")
    args = parser.parse_args()
    try:
        report = inspect(read_local(args.input))
    except (OSError, Invalid):
        report = {
            "status": "FAIL",
            "complete": False,
            "findings": ["input_read_failed"],
        }
    print(json.dumps(report, sort_keys=True, ensure_ascii=True))
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[report["status"]]


import re
import subprocess
import sys

MAX_SOURCE = 2 * 1024 * 1024
MAX_TRANSPORT = 6 * 4 * 1024 * 1024 + 65536


def unique(pairs):
    result = {}
    for k, v in pairs:
        require(k not in result, "duplicate_json_key")
        result[k] = v
    return result


def source_size(value):
    require(isinstance(value, str), "source_string_required")
    try:
        return len(value.encode("utf-8"))
    except UnicodeError:
        raise Invalid("invalid_unicode_source") from None


def analyze(data):
    source = text(data)
    if source.lstrip().startswith("{"):
        try:
            doc = json.loads(
                source,
                object_pairs_hook=unique,
                parse_constant=lambda _: (_ for _ in ()).throw(
                    Invalid("nonfinite_json")
                ),
            )
        except (ValueError, RecursionError):
            raise Invalid("invalid_source_mapping_json") from None
        require(isinstance(doc, dict), "mapping_object_required")
        if doc.get("format") != "yara-local-compile-v1":
            raise Unsupported("unsupported_source_mapping_format")
        require(set(doc) <= {"format", "sources", "includes"}, "unknown_mapping_field")
        sources = doc.get("sources")
        includes = doc.get("includes", {})
    else:
        sources = {"main": source}
        includes = {}
    require(
        isinstance(sources, dict)
        and 0 < len(sources) <= 128
        and isinstance(includes, dict)
        and len(includes) <= 128,
        "source_count_limit",
    )
    total = 0
    for name, value in sources.items():
        require(
            isinstance(name, str)
            and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,127}", name),
            "invalid_namespace",
        )
        require(
            isinstance(value, str) and source_size(value) <= MAX_SOURCE,
            "source_limit",
        )
        total += source_size(value)
    for name, value in includes.items():
        require(
            isinstance(name, str)
            and re.fullmatch(r"[A-Za-z_0-9][A-Za-z_0-9.-]{0,127}", name)
            and ".." not in name,
            "unsafe_include_name",
        )
        require(
            isinstance(value, str) and source_size(value) <= MAX_SOURCE,
            "include_source_limit",
        )
        total += source_size(value)
    require(total <= 4 * 1024 * 1024, "aggregate_source_limit")
    payload = json.dumps({"sources": sources, "includes": includes}).encode()
    require(len(payload) <= MAX_TRANSPORT, "serialized_source_limit")
    try:
        done = subprocess.run(
            [sys.executable, "-m", "yaracompilereview.compiler"],
            input=payload,
            capture_output=True,
            timeout=5,
        )
    except subprocess.TimeoutExpired:
        raise Unsupported("compiler_wall_timeout") from None
    require(len(done.stdout) <= 65536, "compiler_response_limit")
    if done.returncode != 0:
        raise Unsupported("compiler_process_failed_or_resource_limit")
    try:
        report = json.loads(done.stdout)
    except (ValueError, RecursionError):
        raise Unsupported("invalid_compiler_response") from None
    require(
        isinstance(report, dict) and report.get("status") in ("PASS", "FAIL", "OPEN"),
        "invalid_compiler_response",
    )
    report.update(
        {
            "source_count": len(sources),
            "authorized_include_count": len(includes),
            "scope": "Compile YARA rules only with explicit in-memory include mappings; no target scan, sample execution, rule repair or filesystem includes.",
        }
    )
    return report
