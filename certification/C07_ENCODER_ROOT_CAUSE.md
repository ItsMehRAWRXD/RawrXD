# C07_ENCODER_ROOT_CAUSE.md

**Subject:** `RAWR_NATIVE_COMPILER_STAGE1` gate C07 — the first-party assembler and the native PE linker
**Date:** 2026-10-22
**Status:** **C07 CERTIFIED — 10 of 10 assertions pass. The full suite is 160 of 160.**

---

## 1. Result

| gate | assertions | result |
|---|---|---|
| C01 Lexer | 97 | PASS |
| C02 COFF writer | 10 | PASS |
| C03 E2E | 7 | PASS |
| C04 Multi-object | 7 | PASS |
| C05 Relocations | 5 | PASS |
| C06 DLL/exports | 14 | PASS |
| **C07 Assembler E2E** | **10** | **PASS** |
| C08 Negative tests | 10 | PASS |
| **total** | **160** | **PASS** |

`RAWR_NATIVE_COMPILER_STAGE1 = PASS`, process exit code 0.

The C07 path is now closed end to end:

```
assembly source
     |  RawrXD first-party x64 assembler        (src/asm/X64Assembler.cpp)
     v
COFF object
     |  RawrXD native linker                      (toolchain/from_scratch/phase2_linker)
     v
PE32+ executable
     |  Windows loader
     v
kernel32!ExitProcess(42)  ->  process exit code 42
```

and the second program, which exercises arithmetic, a register-to-register
move and a push/pop pair, exits with **41**.

---

## 2. The defects, in the order they were found

### 2.1 The fixture was written with `sizeof` on a pointer

`WriteFixture(const String& path, const char* source)` wrote the fixture with
`sizeof(source) - 1`. `source` is a pointer, so `sizeof(source)` is the
pointer size: 8, and 8 − 1 = **7**. Every fixture was truncated to the first
seven bytes, `"bits 64"`.

The assembler then did exactly what it was told and produced an 82-byte object
with an empty `.text` and one symbol (the file symbol). The linker found no
entry point, used its default stub at `0x1000`, and emitted a 512-byte PE that
Windows refused: *"This app can't run on your PC"*.

**Fix:** the length comes from `strlen`.

### 2.2 `cmd.exe` stripped the outer quotes of the link command

`std::system()` goes through `cmd.exe`, and `cmd.exe` removes the first and the
last quote of a string that begins and ends with one. A command that starts
with a quoted executable path therefore arrived as

```
rawrxd_link.exe" -o "out.exe
```

which `cmd.exe` rejects with *"The filename, directory name, or volume label
syntax is incorrect."* Every shell-invoked stage failed while the assembler —
a native API, no shell — appeared to work, which is what made it look like a
path or linker defect.

**Fix:** the whole command is wrapped in one more pair of quotes
(`WrapForCmd`), and the paths are built with backslashes.

### 2.3 The ALU immediate encodings were wrong

`EncodeAlu` folded the operation into the **opcode** byte instead of into the
ModRM `/digit` field. For `sub` that produced `0x28 | 0x81 = 0xA9`, which is
`TEST rax, imm32`; and the ModRM `reg` field came out as `4`, which is **AND**,
so `add rsp, imm` became `AND r8, imm32`.

```
sub rsp, 40   expected 48 83 EC 28   emitted 48 A9 E0 28 00 00 00
add rsp, 40   expected 48 83 C4 28   emitted 48 81 E0 28 00 00 00
```

**Fix:** the group-1 opcode is fixed (`0x80`/`0x83`/`0x81`) and the operation
travels in the ModRM `reg` field. An immediate that fits in a signed byte uses
the sign-extended form.

### 2.4 `mov reg, imm` mis-selected the register and mangled the immediate

`mov ecx, 42` came out as `B8 01 2A 00 00 00`: the opcode was `0xB8`
(`mov eax, imm32`) and the register number was written as a **separate byte**,
which then became the first byte of the immediate — so 42 became `0x00002A01`.

**Fix:** the destination register is folded into the opcode, `0xB8 + rd`, and
the immediate follows with nothing in front of it.

### 2.5 The memory forms lost their base register

`add [rax], ebx` came out as `01 1D` and `add [rax+8], ebx` as `01 1D` — a
ModRM of `mod=00, rm=101`, the no-base form, with the displacement dropped
entirely. The same defect showed in the MOV memory form (`89 1D`).

**Fix:** the memory operand keeps its base register, and the `mod=00, rm=101`
form emits the disp32 that the encoding requires. The register-against-memory
form uses `base | 0x01`, the 32-bit opcode; emitting the bare `base` would
have selected the 8-bit opcode and the operation would have touched one byte.

Verified encodings after the fix:

```
add  [rax], ebx     01 18
sub  [rax], ebx     29 18
add  [rax+8], ebx   01 58 08
add  ebx, [rax]     01 18
mov  [rbx], ecx     89 0B
mov  [rcx], ecx     89 09
mov  [rsp], ecx     89 0C 24
mov  [rax+8], ecx   89 48 08
```

### 2.6 The test program used a mis-aligned stack frame

With the encoder correct, the produced image loaded and then faulted with
`0xC0000005`. The C07 program reserved 32 bytes of shadow space:

```
sub  rsp, 32
```

At function entry `RSP ≡ 8 (mod 16)`, so `sub rsp, 32` leaves `RSP ≡ 8` at the
`call` — **not 16-byte aligned**, which a Windows API may not tolerate. The
certified L3 fixture uses a `0x28`-byte frame, and its own source says why:
*"32 bytes of Win64 shadow space plus 8 bytes... Every call goes through a
single 0x28-byte frame, so the stack stays aligned."*

**Fix:** the C07 programs use a 40-byte frame, matching the ABI and the
certified fixture.

### 2.7 The C07 build linked a stale assembler

`build_c07_only.bat` compiled only the test and linked the `.obj` files that
happened to be in the output directory. A source fix in the encoder could
therefore be committed, rebuilt in isolation, and still appear to have no
effect — because the linked `X64Assembler.obj` was old. This cost real
diagnosis time and is a trap worth recording.

**Fix:** the script now rebuilds `src/object/CoffWriter.cpp` and
`src/asm/X64Assembler.cpp` from source before linking.

---

## 3. The external-call contract (verified, not assumed)

The user asked that the import representation be checked against the linker's
existing semantics rather than accommodated by changing them. It was.

The assembler emits the **direct** form:

```
E8 05 00 00 00      call rel32
```

with a relocation against `ExitProcess`, and the linker resolves an imported
symbol to its **thunk** RVA:

```c
/* src/.../phase2_linker/import_gen.c */
uint32_t target = sym->needs_thunk ? sym->thunk_rva : sym->iat_rva;
```

and `needs_thunk` is 1 for every symbol except the `__imp_` forms, which
*"point straight at the IAT slot, so no redirect thunk is required for
them."* The linker also documents that the thunk *"targets the IAT slot. After
the loader binds the import, the thunk jumps to the real function."*

So the two representations are both supported and neither required a change
to the linker:

| form | relocation | resolved to | works |
|---|---|---|---|
| `E8 rel32` (what the assembler emits) | REL32 against `ExitProcess` | thunk RVA → `jmp [IAT]` | yes |
| `FF 15 disp32` (what the L3 fixture uses) | REL32 against `__imp_ExitProcess` | IAT RVA → the bound address | yes |

The linker's relocation contract was also checked and needs no change: this
toolchain reads relocations from **per-section relocation tables** pointed at
by the section header, which is exactly what `CoffWriter` emits. The
auxiliary-symbol-entry convention of the wider COFF world is not used here, by
both sides, consistently.

---

## 4. What C07 proves, and what it does not

**It proves:** a first-party x64 assembler, a first-party COFF object writer
and a first-party PE linker work together to produce a Windows executable that
the Windows loader accepts and that exits with a chosen code — through the
linker's own import and thunk machinery, with no external toolchain.

**It does not prove:** that a C++ front end exists. The lexer is certified
separately at C01, but nothing yet connects C++ source to the assembler's
input. That remains the open work, and it is the reason the C07 certificate
must not be read as "the native compiler is finished".

---

## 5. Regression protection

C07 now carries byte-exact instruction assertions of its own, so an encoding
regression is reported as a **byte difference** rather than as a crash:

- the documented instruction bytes of the exit program,
- the memory forms of the ALU operations, byte for byte,
- the negative cases (an unknown instruction and a truncated operand).

The full suite is the regression net: C01–C06 and C08 were not modified, and
the suite is 160/160.

---

## 6. Verification commands

```
compilers\native_compiler\tools\build_stage1.bat
```

builds every unit from source and runs C01–C08. The C07 suite can be run on
its own with:

```
compilers\native_compiler\tools\build_c07_only.bat
```

which rebuilds the assembler and the COFF writer before linking.

Evidence: `certification/RAWR_NATIVE_COMPILER_STAGE1.log`,
`certification/RAWR_NATIVE_C07_CERT_002.json`.
