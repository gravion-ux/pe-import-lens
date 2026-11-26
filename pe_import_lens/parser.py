"""Minimal PE32/PE32+ import directory parser (no third-party deps).

Reads the import table of a Windows PE file and flags imports that are
commonly associated with process injection, dynamic code execution, and
anti-analysis techniques. The file is only parsed, never executed.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

FLAGGED = {
    "VirtualAllocEx": ("high", "Remote memory allocation (injection primitive)"),
    "WriteProcessMemory": ("high", "Cross-process memory write (injection primitive)"),
    "CreateRemoteThread": ("high", "Remote thread creation (injection primitive)"),
    "NtUnmapViewOfSection": ("high", "Section unmapping used in process hollowing"),
    "SetWindowsHookExA": ("medium", "Global hook installation"),
    "SetWindowsHookExW": ("medium", "Global hook installation"),
    "GetAsyncKeyState": ("medium", "Key-state polling (keylogging pattern)"),
    "IsDebuggerPresent": ("low", "Debugger presence check (anti-analysis)"),
    "CheckRemoteDebuggerPresent": ("low", "Remote debugger check (anti-analysis)"),
    "VirtualProtect": ("low", "Memory protection change; review RWX transitions"),
    "ShellExecuteA": ("low", "Shell execution entry point"),
    "ShellExecuteW": ("low", "Shell execution entry point"),
}


@dataclass
class ImportEntry:
    dll: str
    name: str

    def to_dict(self):
        return {"dll": self.dll, "name": self.name}


def _rva_to_offset(sections, rva):
    for vaddr, vsize, raw_ptr, raw_size in sections:
        size = max(vsize, raw_size)
        if vaddr <= rva < vaddr + size:
            return raw_ptr + (rva - vaddr)
    return None


def _read_cstr(data, offset):
    end = data.index(b"\x00", offset)
    return data[offset:end].decode("ascii", errors="replace")


def parse_imports(data: bytes) -> list[ImportEntry]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("not a PE file (missing MZ header)")
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b"PE\x00\x00":
        raise ValueError("not a PE file (missing PE signature)")
    coff = pe_off + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x10B:  # PE32
        dd_base = opt + 96
        thunk_size, ordinal_flag = 4, 0x80000000
    elif magic == 0x20B:  # PE32+
        dd_base = opt + 112
        thunk_size, ordinal_flag = 8, 0x8000000000000000
    else:
        raise ValueError(f"unsupported optional header magic: {magic:#x}")
    import_rva = struct.unpack_from("<I", data, dd_base + 8)[0]
    if import_rva == 0:
        return []
    sections = []
    sec_base = opt + opt_size
    for i in range(num_sections):
        s = sec_base + i * 40
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, s + 8)
        sections.append((vaddr, vsize, raw_ptr, raw_size))
    entries: list[ImportEntry] = []
    desc_off = _rva_to_offset(sections, import_rva)
    if desc_off is None:
        raise ValueError("import directory RVA is outside all sections")
    while True:
        oft_rva, _, _, name_rva, ft_rva = struct.unpack_from("<IIIII", data, desc_off)
        if oft_rva == 0 and name_rva == 0 and ft_rva == 0:
            break
        dll = _read_cstr(data, _rva_to_offset(sections, name_rva))
        thunk_rva = oft_rva or ft_rva
        thunk_off = _rva_to_offset(sections, thunk_rva)
        fmt = "<I" if thunk_size == 4 else "<Q"
        while True:
            value = struct.unpack_from(fmt, data, thunk_off)[0]
            if value == 0:
                break
            if value & ordinal_flag:
                entries.append(ImportEntry(dll, f"ordinal_{value & 0xFFFF}"))
            else:
                name_off = _rva_to_offset(sections, value & 0x7FFFFFFF)
                entries.append(ImportEntry(dll, _read_cstr(data, name_off + 2)))
            thunk_off += thunk_size
        desc_off += 20
    return entries


def flag_imports(entries: list[ImportEntry]) -> list[dict]:
    flagged = []
    for e in entries:
        if e.name in FLAGGED:
            severity, note = FLAGGED[e.name]
            flagged.append({"dll": e.dll, "name": e.name, "severity": severity, "note": note})
    return flagged
