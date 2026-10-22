#!/usr/bin/env python3
"""Offline PE identity and explicit byte-pattern scanner for MCBE client inputs.

This is a small M1 utility. It never downloads or executes game binaries.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path


class InputError(ValueError):
    pass


def parse_pe(data: bytes) -> dict:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise InputError("input is not a valid DOS/PE image (missing MZ header)")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset > len(data) - 24 or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise InputError("invalid or truncated PE header")
    machine, section_count = struct.unpack_from("<HH", data, pe_offset + 4)
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional = pe_offset + 24
    if optional_size < 2 or optional + optional_size > len(data):
        raise InputError("invalid or truncated optional header")
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic not in (0x10B, 0x20B):
        raise InputError(f"unsupported PE optional-header magic: {magic:#x}")
    if section_count > 96:
        raise InputError("unreasonable PE section count")
    section_table = optional + optional_size
    if section_table + section_count * 40 > len(data):
        raise InputError("truncated PE section table")
    sections = []
    for i in range(section_count):
        off = section_table + i * 40
        name = data[off:off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", data, off + 8)
        characteristics = struct.unpack_from("<I", data, off + 36)[0]
        if raw_size and (raw_offset > len(data) or raw_size > len(data) - raw_offset):
            raise InputError(f"section {name!r} exceeds file bounds")
        sections.append({
            "name": name, "virtual_size": virtual_size, "rva": virtual_address,
            "raw_size": raw_size, "raw_offset": raw_offset,
            "characteristics": characteristics
        })
    return {
        "machine": machine,
        "architecture": {0x8664: "x64", 0x14C: "x86", 0xAA64: "arm64"}.get(machine, f"unknown:{machine:#x}"),
        "optional_header": "PE32+" if magic == 0x20B else "PE32",
        "sections": sections,
    }


def parse_pattern(value: str) -> list[int | None]:
    tokens = value.split()
    if not tokens:
        raise InputError("empty signature pattern")
    parsed = []
    for token in tokens:
        if token in ("?", "??"):
            parsed.append(None)
        else:
            try:
                b = int(token, 16)
            except ValueError as exc:
                raise InputError(f"invalid pattern token: {token!r}") from exc
            if not 0 <= b <= 255:
                raise InputError(f"pattern byte out of range: {token!r}")
            parsed.append(b)
    if all(b is None for b in parsed):
        raise InputError("pattern cannot consist only of wildcards")
    return parsed


def scan(data: bytes, pattern: list[int | None], section: dict) -> list[int]:
    start, size = section["raw_offset"], section["raw_size"]
    hay = data[start:start + size]
    n = len(pattern)
    if n > len(hay):
        return []
    matches = []
    for i in range(len(hay) - n + 1):
        if all(want is None or hay[i + j] == want for j, want in enumerate(pattern)):
            matches.append(section["rva"] + i)
    return matches


def run(binary: Path, targets_path: Path, output: Path | None, max_bytes: int) -> dict:
    size = binary.stat().st_size
    if size == 0 or size > max_bytes:
        raise InputError(f"binary size {size} is outside allowed range")
    data = binary.read_bytes()
    pe = parse_pe(data)
    targets_doc = json.loads(targets_path.read_text(encoding="utf-8"))
    if targets_doc.get("schema_version") != 1 or not isinstance(targets_doc.get("targets"), list):
        raise InputError("invalid targets catalogue schema")
    results = []
    for target in targets_doc["targets"]:
        if not isinstance(target, dict) or not target.get("id") or not target.get("pattern"):
            raise InputError("each target must have id and pattern")
        pattern = parse_pattern(target["pattern"])
        sections = [s for s in pe["sections"] if s["characteristics"] & 0x20000000]
        matches = []
        for section in sections:
            matches.extend(scan(data, pattern, section))
        status = "MATCH_UNIQUE" if len(matches) == 1 else "NOT_FOUND" if not matches else "AMBIGUOUS"
        results.append({"id": target["id"], "status": status, "candidate_rvas": [hex(x) for x in matches]})
    report = {
        "schema_version": 1,
        "role": "client",
        "binary": {"name": binary.name, "size_bytes": size, "sha256": hashlib.sha256(data).hexdigest()},
        "pe": pe,
        "catalogue_status": targets_doc.get("status", "unknown"),
        "targets": results,
        "support": "UNVERIFIED"
    }
    encoded = json.dumps(report, indent=2) + "\n"
    if output:
        output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--targets", type=Path, default=Path("compat/targets.json"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--max-bytes", type=int, default=2_147_483_648)
    args = parser.parse_args()
    try:
        report = run(args.binary, args.targets, args.output, args.max_bytes)
    except (OSError, json.JSONDecodeError, InputError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if report["catalogue_status"] == "bootstrap_required":
        print("BLOCKED: target catalogue is empty; no compatibility conclusion can be drawn.", file=sys.stderr)
        return 3
    if any(item["status"] != "MATCH_UNIQUE" for item in report["targets"]):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
