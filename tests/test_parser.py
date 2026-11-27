import struct

import pytest

from pe_import_lens import flag_imports, parse_imports


def build_pe(imports):
    """Build a minimal PE32 with one section holding the import table."""
    section_rva = 0x1000
    # Layout inside section: descriptor(20) + null desc(20) + thunks + names
    offset = 40 + (len(imports) + 1) * 4
    blob = bytearray()
    thunk_rvas = []
    for name in imports:
        name_rva = section_rva + offset
        thunk_rvas.append(name_rva)
        encoded = b"\x00\x00" + name.encode() + b"\x00"
        blob += encoded
        offset += len(encoded)
    dll_name_rva = section_rva + offset
    blob += b"KERNEL32.dll\x00"
    section = bytearray()
    section += struct.pack("<IIIII", section_rva + 40, 0, 0, dll_name_rva, section_rva + 40)
    section += b"\x00" * 20
    for rva in thunk_rvas:
        section += struct.pack("<I", rva)
    section += struct.pack("<I", 0)
    section += blob
    dos = bytearray(0x80)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 224, 0)
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 96 + 8, section_rva)  # import dir RVA
    struct.pack_into("<I", opt, 96 + 12, 40)
    sec = b".rdata\x00\x00" + struct.pack("<IIII", len(section), section_rva, len(section), 0x200) + b"\x00" * 16
    header = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + sec
    return header.ljust(0x200, b"\x00") + bytes(section)


def test_parses_import_names():
    entries = parse_imports(build_pe(["CreateFileA", "VirtualAllocEx"]))
    assert [e.name for e in entries] == ["CreateFileA", "VirtualAllocEx"]
    assert entries[0].dll == "KERNEL32.dll"


def test_flags_injection_imports():
    flagged = flag_imports(parse_imports(build_pe(["VirtualAllocEx", "CreateRemoteThread", "Sleep"])))
    names = {f["name"] for f in flagged}
    assert names == {"VirtualAllocEx", "CreateRemoteThread"}
    assert all(f["severity"] == "high" for f in flagged)


def test_rejects_non_pe():
    with pytest.raises(ValueError):
        parse_imports(b"not a pe file at all, just text padding........")

def test_rejects_non_pe_input():
    with pytest.raises(ValueError):
        parse_imports(b"this is not a PE file")


def test_rejects_empty_input():
    with pytest.raises(ValueError):
        parse_imports(b"")
