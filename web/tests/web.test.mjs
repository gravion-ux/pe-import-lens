import { test } from "node:test";
import assert from "node:assert/strict";
import { parseImports, flagImports, buildSamplePE } from "../app.js";

test("sample PE parses to the expected imports", () => {
  const entries = parseImports(buildSamplePE());
  assert.deepEqual(entries, [
    { dll: "KERNEL32.dll", name: "VirtualAllocEx" },
    { dll: "KERNEL32.dll", name: "CreateRemoteThread" },
    { dll: "KERNEL32.dll", name: "CreateFileW" },
    { dll: "USER32.dll", name: "SetWindowsHookExW" },
    { dll: "USER32.dll", name: "MessageBoxW" },
  ]);
});

test("flagged imports carry severity and notes", () => {
  const flagged = flagImports(parseImports(buildSamplePE()));
  assert.equal(flagged.length, 3);
  const vae = flagged.find((f) => f.name === "VirtualAllocEx");
  assert.equal(vae.severity, "high");
  assert.match(vae.note, /injection/);
  assert.equal(flagged.find((f) => f.name === "SetWindowsHookExW").severity, "medium");
});

test("non-PE input is rejected", () => {
  assert.throws(() => parseImports(new Uint8Array([1, 2, 3])), /missing MZ/);
  const mzOnly = new Uint8Array(0x80);
  mzOnly[0] = 0x4d; mzOnly[1] = 0x5a;
  assert.throws(() => parseImports(mzOnly), /missing PE signature/);
});

test("PE with no import directory returns no entries", () => {
  const pe = buildSamplePE();
  const view = new DataView(pe.buffer);
  view.setUint32(0x80 + 4 + 20 + 96 + 8, 0, true); // zero import RVA
  assert.deepEqual(parseImports(pe), []);
});
