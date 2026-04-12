# SovereignAssembler vs ml64 — parity audit

This document explains **why** the internal assembler is not drop-in equivalent to **Microsoft ml64** (MASM x64), what still triggers the **ml64 fallback** in the IDE, and how to **measure** the gap against your tree’s `.asm` files.

## 1. Different jobs (root cause)

| Aspect | **ml64** (Visual Studio) | **SovereignAssembler** |
|--------|--------------------------|-------------------------|
| Primary output | **COFF `.obj`** (`/c /Fo…`), then **`link.exe`** builds DLL/EXE | **`AssembleAndLink` → PE `.exe` directly**; optional **`AssembleToCOFF` → `.obj`** (subset, for external link) |
| Language | Full **MASM**: `PROC`/`ENDP`, `SEGMENT`/`ENDS`, `OPTION`, `INCLUDE`, macros, `INVOKE`, `EXTERN`/`PUBLIC`, frame prologues, etc. | **Small tokenizer + hand-written encoders**: line-oriented, **no** macro engine, **no** `INCLUDE`, **limited** directives |
| Imports / link | Typical workflow: **libc + kernel32** via link line and `.lib` | **Custom `import dll, f1, f2`** + built **`.idata`**; **`call`** to imported names → **`FF 15` [IAT]** (see `buildIdataSection` / `writePE`) |
| Failure visibility | ml64 errors shown when IDE runs `ml64 …` | **`Win32IDE_AgenticBridge::RunCompilerImpl`**: tries `AssembleAndLink` **first**; on **any** failure, falls through to **ml64** without surfacing sovereign error in the “success” path — so **parity gaps look like “it used ml64”** unless you log `sovereignErr` |

**Conclusion:** Sovereign is a **fast path for tiny, self-contained PE stubs** and **subset** COFF; ml64 is a **full industrial assembler + separate linker**. They will not behave the same until language coverage and link workflow match.

---

## 2. IDE integration (where fallback happens)

```text
src/win32app/Win32IDE_AgenticBridge.cpp
```

For `.asm` / `.s`:

1. Read file (size-capped).
2. **`SovereignAssembler::AssembleAndLink(asmSource, …_sovereign.exe, sovereignErr)`**.
3. **If true** → return success string (sovereign PE path).
4. **Else** → **`ml64.exe /c /Fo…`** (and related flags).

So **anything** that makes `assemble()` throw or `writePE` fail — **unknown mnemonic, unsupported directive, bad memory form, duplicate labels, etc.** — forces **ml64**.

---

## 3. What Sovereign implements today (encoder surface)

Authoritative source: `src/agentic/SovereignAssembler.cpp` (tables near `g_ScalarAluOpcodeMap`, `jccNearSecondByteOr255`, `kInsnEmitByMnemonic`).

**Scalar ALU / test (via `tryLookupScalarAlu`):**  
`add`, `or`, `and`, `sub`, `xor`, `cmp`, `test` — reg/reg, reg/mem, mem/reg, imm (`81`/`83` where applicable); `test` imm uses group **F7 /0**.

**Near conditional jumps:** full **0F 80–8F** set exposed by mnemonic aliases (`jo`, `jb`/`jc`, …, `jg`, …).

**Other opcodes (dispatch table):**  
`ret`, `nop`, `syscall`, `push`, `pop`, `mov` (subset), `movzx`, `movsx`, `lea`, `movsxd`, `jmp`, `call` (non-import and import).

**Directives:** `db`/`dw`/`dd`/`dq`, **`import`** (sovereign-specific), labels `name:`.

**PE features:** `.text` / `.data` / **`.idata`**, import directory, **checksum**; **`call` imported symbol** fixup to IAT.

**Not** MASM-complete: no `PROC`, `ENDP`, `END`, `OPTION`, `INCLUDE`, `ASSUME`, `INVOKE`, `EXTERN`/`PUBLIC` (as ml64 understands them), no structured exception directives, no SIMD **VEX/EVEX** pipeline, no listing/debug info.

---

## 4. What blocks “same as ml64” for repo `.asm` files

Use **`tools/audit_asm_mnemonics.ps1`** (and optionally **`tools/enum_asm_mnemonics.py`**) on `src` + `Ship` to see **first-token** frequency. Typical **ml64-only** needs that Sovereign does **not** satisfy:

1. **Directive / syntax volume** — lines starting with `.` (segment, align, proc) or **`invoke`**, **`extern`**, **`public`**, **`include`** — sovereign tokenizer does not implement the MASM front end.
2. **Instruction coverage** — high-frequency scalars often still missing in sovereign: **`inc`/`dec`**, **`neg`/`not`**, shifts **`shl`/`shr`/`sar`**, **`imul`/`idiv`/`mul`**, **`xchg`**, **`setcc`**, **`cmovcc`**, **`lea`**-level is done but many opcodes from the frequency list are not.
3. **SIMD / AVX** — any `vmovaps`, `vaddps`, etc. requires a **VEX/EVEX** encoder (large project).
4. **Object + link workflow** — ml64 users expect **`.obj` + link** with CRT; sovereign’s happy path is **single PE**. **`AssembleToCOFF`** helps only for sources that already fit the subset.
5. **ABI / prologue** — MASM `PROC` with stack frames and unwind; sovereign does not generate SEH metadata.

---

## 5. How to audit “what stops sovereign” on your tree

1. Run **`powershell -File tools/audit_asm_mnemonics.ps1`** — note top mnemonics and `extern`/`invoke`/`include` counts.
2. Maintain a **supported mnemonic list** (see section 3) and diff: any **top token not in the list** is a **parity gap** until implemented.
3. For IDE behavior: temporarily **log `sovereignErr`** when `AssembleAndLink` fails (same code path as `Win32IDE_AgenticBridge.cpp`) to see **exact** parse/encode errors instead of silent ml64 fallback.
4. Optional: run **`tools/Audit-SovereignVsMl64.ps1`** (if present) to flag lines whose first opcode token is not in the supported set.

---

## 6. Recommended direction (short)

- **Near-term:** extend **scalar** opcodes by frequency (audit script output) + improve **error surfacing** when sovereign fails so you are not guessing why ml64 ran.
- **Medium:** richer **COFF + link** story (`lld` or MSVC `link`) if you need **real** `.obj` parity without reimplementing the linker.
- **Long:** **SIMD** only if your hot paths require it.

This file is the single reference for **“why not ml64 yet”**; update section 3 when `SovereignAssembler.cpp` tables change.
