#!/usr/bin/env python3
"""Build a minimal valid DEX + fake .aab (zip) for smoke-testing check_obfuscation.py.

Creates classes with readable and R8-style short names so the checker can score them.
"""
from __future__ import annotations

import hashlib
import struct
import zipfile
import zlib
from pathlib import Path


def mutf8_encode(s: str) -> bytes:
    # Sufficient for ASCII test identifiers
    return s.encode("utf-8") + b"\x00"


def uleb128(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def align4(buf: bytearray) -> None:
    while len(buf) % 4:
        buf.append(0)


def build_dex(class_descriptors: list[str]) -> bytes:
    """Build a minimal DEX containing empty class_defs for the given L…; descriptors."""
    # Also need java.lang.Object as superclass
    object_desc = "Ljava/lang/Object;"
    strings: list[str] = []
    string_index: dict[str, int] = {}

    def add_str(s: str) -> int:
        if s not in string_index:
            string_index[s] = len(strings)
            strings.append(s)
        return string_index[s]

    type_descs: list[str] = []
    type_index: dict[str, int] = {}

    def add_type(d: str) -> int:
        add_str(d)
        if d not in type_index:
            type_index[d] = len(type_descs)
            type_descs.append(d)
        return type_index[d]

    add_type(object_desc)
    for d in class_descriptors:
        add_type(d)

    # --- data section pieces ---
    data = bytearray()
    string_data_offs: list[int] = []

    for s in strings:
        string_data_offs.append(len(data))
        encoded = mutf8_encode(s)
        # uleb128 utf16 length = number of code units ≈ ascii len for our tests
        data.extend(uleb128(len(s)))
        data.extend(encoded)
    align4(data)

    # We will relocate: header(0x70) + string_ids + type_ids + proto_ids(0) +
    # field_ids(0) + method_ids(0) + class_defs + data
    header_size = 0x70
    string_ids_size = len(strings)
    type_ids_size = len(type_descs)
    proto_ids_size = 0
    field_ids_size = 0
    method_ids_size = 0
    class_defs_size = len(class_descriptors)

    string_ids_off = header_size
    type_ids_off = string_ids_off + string_ids_size * 4
    proto_ids_off = type_ids_off + type_ids_size * 4
    field_ids_off = proto_ids_off + proto_ids_size * 12
    method_ids_off = field_ids_off + field_ids_size * 8
    class_defs_off = method_ids_off + method_ids_size * 8
    data_off = class_defs_off + class_defs_size * 32

    # Fix string_data offsets relative to file = data_off + local
    string_ids = bytearray()
    for off in string_data_offs:
        string_ids.extend(struct.pack("<I", data_off + off))

    type_ids = bytearray()
    for d in type_descs:
        type_ids.extend(struct.pack("<I", string_index[d]))

    class_defs = bytearray()
    object_idx = type_index[object_desc]
    for d in class_descriptors:
        class_idx = type_index[d]
        # class_idx, access_flags(public=1), superclass, interfaces_off=0,
        # source_file_idx=NO_INDEX(0xFFFFFFFF), annotations=0, class_data=0, static=0
        class_defs.extend(
            struct.pack(
                "<IIIIIIII",
                class_idx,
                1,  # public
                object_idx,
                0,
                0xFFFFFFFF,
                0,
                0,
                0,
            )
        )

    file_size = data_off + len(data)

    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    # checksum + signature filled later
    struct.pack_into("<I", header, 32, file_size)
    struct.pack_into("<I", header, 36, header_size)
    struct.pack_into("<I", header, 40, 0x12345678)
    struct.pack_into("<I", header, 44, 0)  # link_size
    struct.pack_into("<I", header, 48, 0)  # link_off
    struct.pack_into("<I", header, 52, 0)  # map_off (optional; 0 ok for our reader)
    struct.pack_into("<I", header, 56, string_ids_size)
    struct.pack_into("<I", header, 60, string_ids_off)
    struct.pack_into("<I", header, 64, type_ids_size)
    struct.pack_into("<I", header, 68, type_ids_off)
    struct.pack_into("<I", header, 72, proto_ids_size)
    struct.pack_into("<I", header, 76, proto_ids_off)
    struct.pack_into("<I", header, 80, field_ids_size)
    struct.pack_into("<I", header, 84, field_ids_off)
    struct.pack_into("<I", header, 88, method_ids_size)
    struct.pack_into("<I", header, 92, method_ids_off)
    struct.pack_into("<I", header, 96, class_defs_size)
    struct.pack_into("<I", header, 100, class_defs_off)
    struct.pack_into("<I", header, 104, len(data))
    struct.pack_into("<I", header, 108, data_off)

    blob = bytearray()
    blob.extend(header)
    blob.extend(string_ids)
    blob.extend(type_ids)
    blob.extend(class_defs)
    blob.extend(data)
    assert len(blob) == file_size

    # signature: SHA-1 of bytes[32:]
    sha = hashlib.sha1(blob[32:]).digest()
    blob[12:32] = sha
    # checksum: adler32 of bytes[12:]
    checksum = zlib.adler32(blob[12:]) & 0xFFFFFFFF
    struct.pack_into("<I", blob, 8, checksum)
    return bytes(blob)


def main() -> None:
    out_dir = Path(__file__).resolve().parent / "testdata"
    out_dir.mkdir(parents=True, exist_ok=True)

    descriptors = [
        # readable app
        "Lcom/example/app/MainActivity;",
        "Lcom/example/app/network/ApiClient;",
        "Lcom/example/app/ui/HomeFragment;",
        # obfuscated app (R8-style)
        "La/a;",
        "La/b;",
        "La/b/c;",
        "Lb/a;",
        "Lc;",
        # library (should be excluded from %)
        "Landroidx/appcompat/app/AppCompatActivity;",
        "Lkotlin/Metadata;",
        "Landroid/os/Bundle;",
        # library that looks short — still excluded by prefix
        "Landroidx/a/a;",
    ]

    dex = build_dex(descriptors)
    dex_path = out_dir / "classes.dex"
    dex_path.write_bytes(dex)

    aab_path = out_dir / "sample.aab"
    with zipfile.ZipFile(aab_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("base/dex/classes.dex", dex)
        zf.writestr("BundleConfig.pb", b"")  # placeholder
        zf.writestr("base/manifest/AndroidManifest.xml", b"")

    print(f"Wrote {dex_path} ({len(dex)} bytes)")
    print(f"Wrote {aab_path}")
    print(f"Classes: {len(descriptors)}")


if __name__ == "__main__":
    main()
