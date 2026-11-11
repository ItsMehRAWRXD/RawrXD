# C07_ROOT_CAUSE.md

**Subject:** `RAWR_NATIVE_COMPILER_STAGE1` gate C07 — end-to-end native toolchain
**Date:** 2026-10-21
**Status:** **NOT CERTIFIED — 6 of 8 assertions pass.** Two defects are closed, four
remain, and all four are in the first-party assembler's instruction encoders and
object writer.

---

## 1. What C07 certifies

```
assembly source
     |
     v
RawrXD first-party x64 assembler  ->  COFF object
     |
     v
RawrXD native linker              ->  PE32+ executable
     |
     v
Windows loader                   ->  kernel32!ExitProcess(42)
     |
     v
process exit code 42
```

Every stage is first-party. The gate is the only one in the suite that runs the
assembler's own encodings all the way to a Windows-loaded process: C03–C06 and
C08 drive the linker with the linker's **own** fixtures (`make_fixtures.c`), and
C01/C02 test the lexer and the COFF writer in isolation. That is why the
assembler's encoding defects survived until C07.

---

## 2. The reported symptom, and what it actually was

The reported failure was:

```
cannot open F:\rawrxd\compilers\build\rawr_stage1/c07_e2e.asm
```

with the missing `.exe` errors cascading from it. That message was **not** the
root cause. It was a *ordering* defect in the harness: the assembly fixture was
written after the assembler had already been invoked. Fixed — both fixtures are
now written before anything runs, and the harness asserts that both exist and
are not empty.

---

## 3. Defect 1 — the fixture was written with `sizeof` on a pointer  → FIXED

`WriteFixture(const String& path, const char* source)` wrote the fixture with:

```cpp
out.write(source, sizeof(source) - 1);
```

`source` is a **pointer**, so `sizeof(source)` is the pointer size (8 on x64),
not the string length. Every fixture was truncated to **seven bytes** — the
first seven bytes of the program, `"bits 64"`:

```
c07_e2e.asm    7 bytes
c07_arith.asm  7 bytes
```

The assembler then quite correctly assembled `"bits 64"` — a `bits` directive
and nothing else — producing:

```
object: 82 bytes
  section[0] '.text'  rawsize=0  rawptr=60        <- no code at all
  symbol[0] 'rawr.obj' cls=103                    <- only the file symbol
```

No `main`, no `ExitProcess`, no relocations. The linker then reported
`entry point 'main' not found` and fell back to its default entry stub at
`0x1000`. The resulting 512-byte PE had one empty section and could not be
loaded: **"This app can't run on your PC"** (and `Access is denied` from
`cmd.exe`).

**Fix:** the length comes from `strlen`, not `sizeof`.

---

## 4. Defect 2 — cmd.exe strips the outer quotes of the command  → FIXED

The harness invoked the linker through `std::system()`, which goes through
`cmd.exe`. `cmd.exe` removes the first and the last quote of a string that
begins and ends with one, so a command whose first character is a quoted
executable path arrived as:

```
rawrxd_link.exe" -o "out.exe
```

which `cmd.exe` rejects with *"The filename, directory name, or volume label
syntax is incorrect."* Every shell-invoked stage of C07 failed this way while
the assembler (a native API, no shell) appeared to work — which is what made it
look like a path or linker defect.

**Fix:** the whole command is wrapped in one more pair of quotes
(`WrapForCmd`), so the stripping lands on the wrapper instead of on the path.
Paths are also built with backslashes, because `cmd.exe` does not accept a
forward slash in a path either.

---

## 5. Defect 3 — the assembler's instruction encoders are wrong  → OPEN

With the harness fixed, the assembler and the linker both succeed, and the
produced PE is a well-formed PE32+ image that Windows now **loads**:

```
[linker] phase 1 complete: 1 object file(s) loaded
[linker] phase 2 complete: 3 merged section(s), next RVA=0x4000
[linker] phase 2.5 complete: 1 DLL(s), 1 symbol(s), 1 thunk(s)
[reloc]   Applied 1 relocations, 0 errors
[pe_writer] c07_e2e.exe: 2048 bytes, 2 sections, entry=0x1000, base=0x140000000
```

It then dies with `0xC0000005` (access violation) instead of exiting 42.

**The cause is the machine code.** Byte-for-byte against the fixture that the
linker's own suite certifies at gate L3:

| instruction | certified fixture | the first-party assembler |
|---|---|---|
| `sub rsp, 32` | `48 83 EC 20` | `48 A9 E0 20 00 00 00` |
| `mov ecx, 42` | `B9 2A 00 00 00` | `B8 01 2A 00 00 00` |
| `call ExitProcess` | `FF 15 00 00 00 00` (IAT-indirect) | `E8 00 00 00 00` (rel32, no relocation) |
| `add rsp, 32` | `48 83 C4 20` | `48 81 E0 20 00 00 00` |

Three distinct encoder faults are visible:

1. **`sub rsp, imm` is encoded as a `TEST`.** `48 A9 …` is `TEST r/m64, imm32`
   (opcode `0xA9`); `sub` is `0x81`/`0x83` with `/5`. The ModRM `reg` field is
   `4` in both the `sub` and the `add` case, and `4` is **AND** — so `add rsp,
   imm` came out as `AND r8, imm32` (`48 81 E0 …`). The ALU opcode table is
   selecting the wrong entry, and the `sub` case picks the `TEST` opcode with
   the AND `/reg` field.

2. **`mov reg, imm` mis-selects the register and mangles the immediate.**
   `B8` is `mov eax, imm32`; `mov ecx, imm32` is `B9`. The emitted bytes are
   `B8 01 2A 00 00 00` — one byte too long, with a stray `01` before the
   immediate, so the value 42 became `0x00002A01`.

3. **`call <symbol>` emits a direct `rel32` call and the relocation is never
   written.** The in-memory object carries one relocation
   (`relocs=1` in `.text`), but the written COFF object has **no auxiliary
   symbol entries at all** (`aux=0` for every symbol), so the linker has
   nothing to patch. The certified fixture instead uses the IAT-indirect form
   `FF 15` with a relocation to the import slot.

The object layout itself is sound — it is structurally equivalent to the
certified fixture (same machine type, same section count, same symbol count,
same file-symbol shape) — so the linker is not at fault, and the PE writer is
not at fault. The fault is upstream of both, in `EncodeAlu`, `EncodeMov`, the
call encoding, and the relocation writer in `assembleX64File`.

---

## 6. Gate accounting

Eight assertions, each recording exactly one result, none conditional:

| # | assertion | result |
|---|---|---|
| 1 | both assembly fixtures were written and are not empty | PASS |
| 2 | the first-party assembler produced a COFF object | PASS |
| 3 | the native linker produced an executable | PASS |
| 4 | the executable ran and exited with 42 | **FAIL** |
| 5 | the arithmetic program assembled | PASS |
| 6 | the arithmetic program produced 41 | **FAIL** |
| 7 | the assembler rejects an unknown instruction | PASS |
| 8 | the assembler rejects a truncated operand | PASS |

The two failures are one root cause: the encoded code is invalid, so neither
program reaches `ExitProcess` with the right value.

The earlier "the first-party assembler check appears as both `[FAIL]` and
`[PASS]`" symptom is also resolved: the result count no longer depends on
whether an earlier stage succeeded, because every assertion is recorded
unconditionally.

---

## 7. What is required to close C07

1. **`EncodeAlu`**: select the correct opcode and `/reg` field for `add`,
   `sub`, `and` (and the rest of the table). `sub` must not select `0xA9`.
2. **`EncodeMov`**: the opcode must be `0xB8 + reg`, and the immediate must be
   written as four bytes with nothing in front of it.
3. **The call encoding**: `call <external symbol>` must carry a relocation.
   Either emit the IAT-indirect form `FF 15` with a relocation against the
   import slot, as the certified fixture does, or emit `E8` **and** write the
   relocation.
4. **`assembleX64File`**: write the relocation entries. The in-memory
   `AsmSection::relocations` is populated, but the written object has no
   auxiliary symbol entries, so the relocation is lost between the assembler and
   the COFF writer.
5. **Regression test**: C07 is the gate for this. It should also assert the
   exact encoded bytes for one program, so an encoding regression is reported as
   a byte difference rather than as a crash.

---

## 8. Verification

- The harness builds and runs from `native_compiler\tools\build_c07_only.bat`,
  using the same compiler flags as `build_stage1.bat`.
- The two closed defects are covered by the gate itself: the fixture check
  (assertion 1) catches the truncation, and the link assertion (assertion 3)
  catches the quoting defect.
- The C01–C06 and C08 implementations were not modified.
