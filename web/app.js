// pe-import-lens web — PE import table parser, 100% client-side.
// Mirrors pe_import_lens/parser.py. The file is only parsed, never executed,
// and never leaves the browser.

export const FLAGGED = {
  VirtualAllocEx: ["high", "Remote memory allocation (injection primitive)"],
  WriteProcessMemory: ["high", "Cross-process memory write (injection primitive)"],
  CreateRemoteThread: ["high", "Remote thread creation (injection primitive)"],
  NtUnmapViewOfSection: ["high", "Section unmapping used in process hollowing"],
  SetWindowsHookExA: ["medium", "Global hook installation"],
  SetWindowsHookExW: ["medium", "Global hook installation"],
  GetAsyncKeyState: ["medium", "Key-state polling (keylogging pattern)"],
  IsDebuggerPresent: ["low", "Debugger presence check (anti-analysis)"],
  CheckRemoteDebuggerPresent: ["low", "Remote debugger check (anti-analysis)"],
  VirtualProtect: ["low", "Memory protection change; review RWX transitions"],
  ShellExecuteA: ["low", "Shell execution entry point"],
  ShellExecuteW: ["low", "Shell execution entry point"],
};

function rvaToOffset(sections, rva) {
  for (const [vaddr, vsize, rawPtr, rawSize] of sections) {
    const size = Math.max(vsize, rawSize);
    if (vaddr <= rva && rva < vaddr + size) return rawPtr + (rva - vaddr);
  }
  return null;
}

function readCstr(data, offset) {
  let end = offset;
  while (end < data.length && data[end] !== 0) end++;
  let s = "";
  for (let i = offset; i < end; i++) s += String.fromCharCode(data[i]);
  return s;
}

export function parseImports(input) {
  const data = input instanceof Uint8Array ? input : new Uint8Array(input);
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const u16 = (o) => view.getUint16(o, true);
  const u32 = (o) => view.getUint32(o, true);
  const u64 = (o) => view.getBigUint64(o, true);

  if (data.length < 0x40 || data[0] !== 0x4d || data[1] !== 0x5a) {
    throw new Error("not a PE file (missing MZ header)");
  }
  const peOff = u32(0x3c);
  if (!(data[peOff] === 0x50 && data[peOff + 1] === 0x45 && data[peOff + 2] === 0 && data[peOff + 3] === 0)) {
    throw new Error("not a PE file (missing PE signature)");
  }
  const coff = peOff + 4;
  const numSections = u16(coff + 2);
  const optSize = u16(coff + 16);
  const opt = coff + 20;
  const magic = u16(opt);
  let ddBase, thunkSize, ordinalFlag;
  if (magic === 0x10b) { ddBase = opt + 96; thunkSize = 4; ordinalFlag = 0x80000000n; }
  else if (magic === 0x20b) { ddBase = opt + 112; thunkSize = 8; ordinalFlag = 0x8000000000000000n; }
  else throw new Error(`unsupported optional header magic: 0x${magic.toString(16)}`);

  const importRva = u32(ddBase + 8);
  if (importRva === 0) return [];

  const sections = [];
  const secBase = opt + optSize;
  for (let i = 0; i < numSections; i++) {
    const s = secBase + i * 40;
    sections.push([u32(s + 12), u32(s + 8), u32(s + 20), u32(s + 16)]); // vaddr, vsize, rawPtr, rawSize
  }

  const entries = [];
  let descOff = rvaToOffset(sections, importRva);
  if (descOff === null) throw new Error("import directory RVA is outside all sections");
  while (true) {
    const oftRva = u32(descOff);
    const nameRva = u32(descOff + 12);
    const ftRva = u32(descOff + 16);
    if (oftRva === 0 && nameRva === 0 && ftRva === 0) break;
    const dll = readCstr(data, rvaToOffset(sections, nameRva));
    let thunkOff = rvaToOffset(sections, oftRva || ftRva);
    while (true) {
      const value = thunkSize === 4 ? BigInt(u32(thunkOff)) : u64(thunkOff);
      if (value === 0n) break;
      if (value & ordinalFlag) {
        entries.push({ dll, name: `ordinal_${Number(value & 0xffffn)}` });
      } else {
        const nameOff = rvaToOffset(sections, Number(value & 0x7fffffffn));
        entries.push({ dll, name: readCstr(data, nameOff + 2) });
      }
      thunkOff += thunkSize;
    }
    descOff += 20;
  }
  return entries;
}

export function flagImports(entries) {
  const flagged = [];
  for (const e of entries) {
    if (e.name in FLAGGED) {
      const [severity, note] = FLAGGED[e.name];
      flagged.push({ dll: e.dll, name: e.name, severity, note });
    }
  }
  return flagged;
}

// Build a minimal synthetic PE32 with a real import directory, for the demo
// button and tests. Imports: KERNEL32.dll (VirtualAllocEx, CreateRemoteThread,
// CreateFileW) and USER32.dll (SetWindowsHookExW, MessageBoxW).
export function buildSamplePE() {
  const SECTION_RVA = 0x1000;
  const SECTION_OFF = 0x200;
  const PE_OFF = 0x80;
  const OPT_SIZE = 0xe0;
  const buf = new Uint8Array(0x600);
  const view = new DataView(buf.buffer);
  const put16 = (o, v) => view.setUint16(o, v, true);
  const put32 = (o, v) => view.setUint32(o, v, true);
  const putStr = (o, s) => { for (let i = 0; i < s.length; i++) buf[o + i] = s.charCodeAt(i); buf[o + s.length] = 0; };

  buf[0] = 0x4d; buf[1] = 0x5a; // MZ
  put32(0x3c, PE_OFF);
  putStr(PE_OFF, "PE");
  const coff = PE_OFF + 4;
  put16(coff + 2, 1); // one section
  put16(coff + 16, OPT_SIZE);
  const opt = coff + 20;
  put16(opt, 0x10b); // PE32
  put32(opt + 96 + 8, SECTION_RVA); // import directory RVA (data directory #1)
  const sec = opt + OPT_SIZE;
  putStr(sec, ".rdata");
  put32(sec + 8, 0x400); // virtual size
  put32(sec + 12, SECTION_RVA);
  put32(sec + 16, 0x400); // raw size
  put32(sec + 20, SECTION_OFF);

  const rva = (off) => SECTION_RVA + (off - SECTION_OFF);
  // Layout inside the section:
  //   +0x00 import descriptors (3 x 20 bytes, last one zeroed)
  //   +0x40 KERNEL32 thunks, +0x60 USER32 thunks
  //   +0x80 hint/name entries, then DLL name strings
  const desc = SECTION_OFF;
  const kThunk = SECTION_OFF + 0x40;
  const uThunk = SECTION_OFF + 0x60;
  let cursor = SECTION_OFF + 0x80;
  const nameEntry = (name) => {
    const off = cursor;
    put16(off, 0); // hint
    putStr(off + 2, name);
    cursor += 2 + name.length + 1;
    if (cursor % 2) cursor++;
    return rva(off);
  };
  const kNames = ["VirtualAllocEx", "CreateRemoteThread", "CreateFileW"].map(nameEntry);
  const uNames = ["SetWindowsHookExW", "MessageBoxW"].map(nameEntry);
  const kDllOff = cursor; putStr(kDllOff, "KERNEL32.dll"); cursor += 14;
  const uDllOff = cursor; putStr(uDllOff, "USER32.dll");

  kNames.forEach((n, i) => put32(kThunk + i * 4, n));
  put32(kThunk + kNames.length * 4, 0);
  uNames.forEach((n, i) => put32(uThunk + i * 4, n));
  put32(uThunk + uNames.length * 4, 0);

  // Descriptor 0: KERNEL32
  put32(desc + 0, rva(kThunk));
  put32(desc + 12, rva(kDllOff));
  put32(desc + 16, rva(kThunk));
  // Descriptor 1: USER32
  put32(desc + 20, rva(uThunk));
  put32(desc + 32, rva(uDllOff));
  put32(desc + 36, rva(uThunk));
  // Descriptor 2 stays zeroed (terminator).
  return buf;
}

// ---- UI (browser only) ----
if (typeof document !== "undefined") {
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  function render(bytes, label) {
    const out = $("results");
    try {
      const entries = parseImports(bytes);
      const flagged = flagImports(entries);
      const byDll = new Map();
      for (const e of entries) {
        if (!byDll.has(e.dll)) byDll.set(e.dll, []);
        byDll.get(e.dll).push(e.name);
      }
      const flagRows = flagged.map((f) =>
        `<div class="id-row"><span class="chip sev-${esc(f.severity)}">${esc(f.severity)}</span>
         <code>${esc(f.dll)}!${esc(f.name)}</code><span class="muted">${esc(f.note)}</span></div>`).join("");
      const dllPanels = [...byDll.entries()].map(([dll, names]) => `
        <div class="panel"><h3>${esc(dll)} (${names.length})</h3>
        <pre>${esc(names.join("\n"))}</pre></div>`).join("");
      out.innerHTML = `
        <div class="panel"><strong>${esc(label)}</strong> — ${entries.length} import(s) across ${byDll.size} DLL(s);
        ${flagged.length} flagged.</div>
        ${flagged.length ? `<div class="panel"><h3>Flagged imports</h3>${flagRows}</div>` : '<div class="panel clean">No flagged imports.</div>'}
        ${dllPanels}`;
    } catch (e) {
      out.innerHTML = `<div class="panel error">${esc(e.message)}</div>`;
    }
  }

  async function handleFile(file) {
    if (!file) return;
    render(new Uint8Array(await file.arrayBuffer()), file.name);
  }

  $("file").addEventListener("change", (e) => handleFile(e.target.files[0]));
  const drop = $("drop");
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => {
    e.preventDefault(); drop.classList.remove("over");
    handleFile(e.dataTransfer.files[0]);
  });
  $("sample").addEventListener("click", () => render(buildSamplePE(), "sample.exe (synthetic)"));
}
