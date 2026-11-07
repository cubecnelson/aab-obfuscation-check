#!/usr/bin/env python3
"""Estimate R8/ProGuard-style obfuscation percentage from an Android App Bundle (.aab).

Unzips the AAB (ZIP), finds DEX under */dex/*.dex (base + feature modules),
parses class (and optionally method) names from the DEX binary format, then
reports how many look obfuscated vs readable.

No Android SDK / androguard required — pure Python 3.9+.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
import tempfile
import zipfile
from collections import Counter
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Sequence, Set, Tuple

# ---------------------------------------------------------------------------
# Heuristics
# ---------------------------------------------------------------------------

# Framework / runtime packages — usually not app code; report separately.
DEFAULT_EXCLUDE_PREFIXES = (
    "android.",
    "androidx.",
    "com.android.",
    "com.google.android.",
    "com.google.gson.",
    "com.google.protobuf.",
    "com.google.common.",
    "com.google.firebase.",
    "com.google.crypto.",
    "dalvik.",
    "java.",
    "javax.",
    "jdk.",
    "kotlin.",
    "kotlinx.",
    "org.jetbrains.",
    "org.intellij.",
    "org.json.",
    "org.xml.",
    "org.xmlpull.",
    "org.apache.",
    "org.w3c.",
    "sun.",
    "libcore.",
)

# Simple class name looks like R8 short name: a, ab, abc (1–3 lowercase letters),
# optionally with trailing digits (a1, ab2) which R8 sometimes emits.
_OBF_SIMPLE = re.compile(r"^[a-z]{1,3}\d*$")
# Package segment is a single lowercase letter (or letter+digit): a, b, c1
_OBF_SEGMENT = re.compile(r"^[a-z]\d*$")
# Entire binary name like a.b.c or a.b.C (last can be short too)
_OBF_FULL_PKG = re.compile(r"^(?:[a-z]\d*\.)+[a-zA-Z]\w*$")


def descriptor_to_binary_name(desc: str) -> Optional[str]:
    """Convert DEX type descriptor 'Lcom/foo/Bar;' → 'com.foo.Bar'. Arrays/primitives → None."""
    if not desc or not desc.startswith("L") or not desc.endswith(";"):
        return None
    return desc[1:-1].replace("/", ".")


def is_obfuscated_class(binary_name: str) -> bool:
    """Heuristic: class looks R8/ProGuard-obfuscated."""
    if not binary_name:
        return False
    parts = binary_name.split(".")
    simple = parts[-1]

    # Outer simple name is short obfuscated token
    if _OBF_SIMPLE.match(simple):
        # Prefer also short package segments when present (a.b.c)
        if len(parts) == 1:
            return True
        # All package segments short single-letter style → strong signal
        if all(_OBF_SEGMENT.match(p) for p in parts[:-1]):
            return True
        # Mixed: still count short simple name under short-ish parent as obfuscated
        # e.g. com.example.a — weaker; only count if majority of segments are short
        short_segs = sum(1 for p in parts if _OBF_SEGMENT.match(p) or _OBF_SIMPLE.match(p))
        return short_segs >= max(2, len(parts) // 2 + 1)

    # Fully short package path ending in longer but still suspicious? skip
    # Inner classes: Outer$a or a$b
    if "$" in simple:
        outer, _, inner = simple.partition("$")
        if _OBF_SIMPLE.match(outer) or _OBF_SIMPLE.match(inner.split("$")[0]):
            return True

    return False


def is_obfuscated_method(name: str) -> bool:
    if name in ("<init>", "<clinit>"):
        return False
    return bool(_OBF_SIMPLE.match(name))


def excluded_by_prefix(binary_name: str, prefixes: Sequence[str]) -> bool:
    return any(binary_name == p[:-1] or binary_name.startswith(p) for p in prefixes if p)


# ---------------------------------------------------------------------------
# Minimal DEX reader (class + method names)
# ---------------------------------------------------------------------------

class DexError(Exception):
    pass


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def _uleb128(data: bytes, off: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if off >= len(data):
            raise DexError("truncated ULEB128")
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
        if shift > 35:
            raise DexError("ULEB128 too long")
    return result, off


def _mutf8_decode(data: bytes, off: int, byte_count: int) -> str:
    # DEX uses MUTF-8; for ASCII identifiers this is fine; handle common cases.
    end = off + byte_count
    raw = data[off:end]
    # Strip possible NUL (MUTF-8 encodes \0 as c0 80; rare in class names)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace")


@dataclass
class DexClassInfo:
    binary_name: str
    descriptor: str
    method_names: List[str] = field(default_factory=list)


@dataclass
class DexFileInfo:
    path: str
    classes: List[DexClassInfo]


def parse_dex(data: bytes, source: str = "<dex>") -> DexFileInfo:
    if len(data) < 0x70:
        raise DexError(f"{source}: file too small")
    if not data.startswith(b"dex\n"):
        raise DexError(f"{source}: not a DEX file (bad magic)")

    endian = _u32(data, 40)
    if endian != 0x12345678:
        raise DexError(f"{source}: unsupported endian {endian:#x}")

    string_ids_size = _u32(data, 56)
    string_ids_off = _u32(data, 60)
    type_ids_size = _u32(data, 64)
    type_ids_off = _u32(data, 68)
    # proto 72/76 unused for class names
    field_ids_size = _u32(data, 80)
    field_ids_off = _u32(data, 84)
    method_ids_size = _u32(data, 88)
    method_ids_off = _u32(data, 92)
    class_defs_size = _u32(data, 96)
    class_defs_off = _u32(data, 100)

    def string_at(idx: int) -> str:
        if idx < 0 or idx >= string_ids_size:
            raise DexError(f"{source}: string_id {idx} out of range")
        soff = _u32(data, string_ids_off + idx * 4)
        length, p = _uleb128(data, soff)
        # length is UTF-16 code unit count; read until NUL for safety
        # Prefer reading declared MUTF-8 bytes until 0
        start = p
        while p < len(data) and data[p] != 0:
            p += 1
        return _mutf8_decode(data, start, p - start)

    def type_descriptor(type_idx: int) -> str:
        if type_idx < 0 or type_idx >= type_ids_size:
            raise DexError(f"{source}: type_id {type_idx} out of range")
        str_idx = _u32(data, type_ids_off + type_idx * 4)
        return string_at(str_idx)

    # method_ids: class_idx(u16), proto_idx(u16), name_idx(u32) — 8 bytes
    def method_name(method_idx: int) -> str:
        if method_idx < 0 or method_idx >= method_ids_size:
            return "?"
        base = method_ids_off + method_idx * 8
        name_idx = _u32(data, base + 4)
        return string_at(name_idx)

    classes: List[DexClassInfo] = []
    for i in range(class_defs_size):
        base = class_defs_off + i * 32
        class_idx = _u32(data, base + 0)
        class_data_off = _u32(data, base + 24)
        desc = type_descriptor(class_idx)
        binary = descriptor_to_binary_name(desc)
        if binary is None:
            continue
        methods: List[str] = []
        if class_data_off:
            try:
                methods = _read_class_method_names(data, class_data_off, method_name)
            except DexError:
                methods = []
        classes.append(DexClassInfo(binary_name=binary, descriptor=desc, method_names=methods))

    return DexFileInfo(path=source, classes=classes)


def _read_class_method_names(data: bytes, off: int, method_name_fn) -> List[str]:
    static_fields_size, off = _uleb128(data, off)
    instance_fields_size, off = _uleb128(data, off)
    direct_methods_size, off = _uleb128(data, off)
    virtual_methods_size, off = _uleb128(data, off)

    def skip_fields(count: int, o: int) -> int:
        field_idx = 0
        for _ in range(count):
            diff, o = _uleb128(data, o)
            field_idx += diff
            _, o = _uleb128(data, o)  # access_flags
        return o

    def read_methods(count: int, o: int) -> Tuple[List[str], int]:
        names: List[str] = []
        method_idx = 0
        for _ in range(count):
            diff, o = _uleb128(data, o)
            method_idx += diff
            _, o = _uleb128(data, o)  # access_flags
            code_off, o = _uleb128(data, o)
            names.append(method_name_fn(method_idx))
            _ = code_off
        return names, o

    off = skip_fields(static_fields_size, off)
    off = skip_fields(instance_fields_size, off)
    direct, off = read_methods(direct_methods_size, off)
    virtual, off = read_methods(virtual_methods_size, off)
    return direct + virtual


# ---------------------------------------------------------------------------
# AAB / ZIP extraction
# ---------------------------------------------------------------------------

DEX_NAME_RE = re.compile(r"(^|/)dex/classes\d*\.dex$", re.IGNORECASE)


def iter_dex_from_aab(aab_path: Path) -> Iterator[Tuple[str, bytes]]:
    """Yield (member_name, dex_bytes) from an .aab (or .apk / plain zip of dex)."""
    if not aab_path.is_file():
        raise FileNotFoundError(aab_path)

    # Plain .dex file
    if aab_path.suffix.lower() == ".dex":
        yield (aab_path.name, aab_path.read_bytes())
        return

    with zipfile.ZipFile(aab_path, "r") as zf:
        names = zf.namelist()
        dex_members = [n for n in names if DEX_NAME_RE.search(n) or n.endswith(".dex")]
        # Prefer module dex/ paths; de-dup
        seen = set()
        ordered = []
        for n in names:
            if n in seen:
                continue
            if DEX_NAME_RE.search(n) or (
                n.endswith(".dex") and "/" in n and "dex/" in n.replace("\\", "/")
            ):
                seen.add(n)
                ordered.append(n)
        # Fallback: any *.dex at root (APK style classes.dex)
        if not ordered:
            for n in names:
                base = n.rsplit("/", 1)[-1]
                if re.match(r"classes\d*\.dex$", base, re.I):
                    ordered.append(n)

        if not ordered:
            raise DexError(
                f"No DEX found in {aab_path}. Expected base/dex/classes*.dex "
                f"(AAB) or classes*.dex (APK). Members sample: {names[:12]}"
            )

        for n in ordered:
            yield (n, zf.read(n))


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

@dataclass
class AnalysisResult:
    aab: str
    dex_files: List[str]
    total_classes: int
    app_classes: int
    library_classes: int
    obfuscated_app_classes: int
    readable_app_classes: int
    obfuscation_percent: float
    library_obfuscated: int
    total_methods_app: int
    obfuscated_methods_app: int
    method_obfuscation_percent: Optional[float]
    sample_obfuscated: List[str]
    sample_readable: List[str]
    by_dex: List[dict]
    exclude_prefixes: List[str]


def analyze(
    aab_path: Path,
    exclude_prefixes: Sequence[str] = DEFAULT_EXCLUDE_PREFIXES,
    include_methods: bool = True,
    sample_limit: int = 12,
) -> AnalysisResult:
    dex_infos: List[DexFileInfo] = []
    dex_names: List[str] = []
    by_dex: List[dict] = []

    for member, blob in iter_dex_from_aab(aab_path):
        info = parse_dex(blob, source=member)
        dex_infos.append(info)
        dex_names.append(member)

        app_obf = app_read = lib = lib_obf = 0
        for c in info.classes:
            if excluded_by_prefix(c.binary_name, exclude_prefixes):
                lib += 1
                if is_obfuscated_class(c.binary_name):
                    lib_obf += 1
            else:
                if is_obfuscated_class(c.binary_name):
                    app_obf += 1
                else:
                    app_read += 1
        by_dex.append(
            {
                "dex": member,
                "classes": len(info.classes),
                "app_obfuscated": app_obf,
                "app_readable": app_read,
                "library": lib,
            }
        )

    all_classes = [c for d in dex_infos for c in d.classes]
    # De-dup by binary name across dex splits (same class shouldn't repeat, but be safe)
    seen: Set[str] = set()
    unique: List[DexClassInfo] = []
    for c in all_classes:
        if c.binary_name in seen:
            continue
        seen.add(c.binary_name)
        unique.append(c)

    app = [c for c in unique if not excluded_by_prefix(c.binary_name, exclude_prefixes)]
    libs = [c for c in unique if excluded_by_prefix(c.binary_name, exclude_prefixes)]
    app_obf_list = [c for c in app if is_obfuscated_class(c.binary_name)]
    app_read_list = [c for c in app if not is_obfuscated_class(c.binary_name)]
    lib_obf = sum(1 for c in libs if is_obfuscated_class(c.binary_name))

    app_n = len(app)
    obf_n = len(app_obf_list)
    pct = (100.0 * obf_n / app_n) if app_n else 0.0

    method_total = method_obf = 0
    method_pct: Optional[float] = None
    if include_methods:
        for c in app:
            for m in c.method_names:
                method_total += 1
                if is_obfuscated_method(m):
                    method_obf += 1
        method_pct = (100.0 * method_obf / method_total) if method_total else 0.0

    return AnalysisResult(
        aab=str(aab_path),
        dex_files=dex_names,
        total_classes=len(unique),
        app_classes=app_n,
        library_classes=len(libs),
        obfuscated_app_classes=obf_n,
        readable_app_classes=len(app_read_list),
        obfuscation_percent=round(pct, 2),
        library_obfuscated=lib_obf,
        total_methods_app=method_total,
        obfuscated_methods_app=method_obf,
        method_obfuscation_percent=None if method_pct is None else round(method_pct, 2),
        sample_obfuscated=[c.binary_name for c in app_obf_list[:sample_limit]],
        sample_readable=[c.binary_name for c in app_read_list[:sample_limit]],
        by_dex=by_dex,
        exclude_prefixes=list(exclude_prefixes),
    )


def format_report(r: AnalysisResult) -> str:
    lines = [
        f"AAB/APK/DEX : {r.aab}",
        f"DEX files   : {len(r.dex_files)}",
    ]
    for d in r.dex_files:
        lines.append(f"  - {d}")
    lines += [
        "",
        f"Total classes (unique) : {r.total_classes}",
        f"  Library / SDK        : {r.library_classes}  (excluded from %)",
        f"  App / other          : {r.app_classes}",
        f"    Obfuscated         : {r.obfuscated_app_classes}",
        f"    Readable           : {r.readable_app_classes}",
        "",
        f">>> App class obfuscation : {r.obfuscation_percent:.2f}%",
    ]
    if r.method_obfuscation_percent is not None:
        lines += [
            f">>> App method obfuscation: {r.method_obfuscation_percent:.2f}% "
            f"({r.obfuscated_methods_app}/{r.total_methods_app})",
        ]
    lines.append(
        f"(library classes that also look obfuscated: {r.library_obfuscated} — not in %)"
    )
    if r.sample_obfuscated:
        lines.append("")
        lines.append("Sample obfuscated (app):")
        for n in r.sample_obfuscated:
            lines.append(f"  · {n}")
    if r.sample_readable:
        lines.append("")
        lines.append("Sample readable (app):")
        for n in r.sample_readable:
            lines.append(f"  · {n}")
    if r.by_dex:
        lines.append("")
        lines.append("Per DEX:")
        for row in r.by_dex:
            lines.append(
                f"  {row['dex']}: classes={row['classes']} "
                f"app_obf={row['app_obfuscated']} app_readable={row['app_readable']} "
                f"lib={row['library']}"
            )
    lines.append("")
    lines.append(
        "Note: heuristic only (short R8-style names). Not a guarantee of security."
    )
    return "\n".join(lines)


def result_to_jsonable(r: AnalysisResult) -> dict:
    return asdict(r)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="check_obfuscation",
        description="Estimate DEX obfuscation percentage from an Android .aab (or .apk / .dex).",
    )
    p.add_argument("aab", type=Path, help="Path to .aab / .apk / .dex")
    p.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON instead of text report",
    )
    p.add_argument(
        "--no-methods",
        action="store_true",
        help="Skip method-name heuristics (faster / smaller output)",
    )
    p.add_argument(
        "--include-library-in-percent",
        action="store_true",
        help="Do not exclude android/androidx/kotlin/… from the percentage denominator",
    )
    p.add_argument(
        "--exclude-prefix",
        action="append",
        default=[],
        metavar="PREFIX",
        help="Extra package prefix to exclude (repeatable), e.g. com.squareup.",
    )
    p.add_argument(
        "--sample",
        type=int,
        default=12,
        help="How many sample class names to show (default 12)",
    )
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    path: Path = args.aab
    if not path.exists():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2

    prefixes: List[str] = []
    if not args.include_library_in_percent:
        prefixes.extend(DEFAULT_EXCLUDE_PREFIXES)
    for pfx in args.exclude_prefix:
        if not pfx.endswith("."):
            pfx = pfx + "."
        prefixes.append(pfx)

    try:
        result = analyze(
            path,
            exclude_prefixes=prefixes,
            include_methods=not args.no_methods,
            sample_limit=args.sample,
        )
    except (DexError, zipfile.BadZipFile, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result_to_jsonable(result), indent=2, ensure_ascii=False))
    else:
        print(format_report(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
