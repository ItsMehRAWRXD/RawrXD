# RAWR_NATIVE_COMPILER_STAGE2_001

**Date:** 2026-10-22
**Branch:** `feature/native-compiler-stage2` (merged with `preservation/source-baseline-20261021`)
**Result:** **232 checks, 0 failures.** Stage 1: 161/161. Stage 2: 21/21. C09 provenance: 6/6. C10 preprocessor: 44/44. `RAWR_NATIVE_COMPILER_STAGE1 = PASS`.

---

## 1. What this milestone is

Stage 1 certified the components. Stage 2 connects them into the first complete
source language pipeline:

```
C source
   |  rawr_c        the C front end          (new)
   v
.asm
   |  rawr_asm      the certified assembler  (new driver over the existing engine)
   v
.obj
   |  rawrxd_link   the certified native linker
   v
.exe   ->  Windows runs it  ->  the exit code is exactly what the program returned
```

Every stage is first-party. The proof is one program:

```c
int main(void) { return 42; }
```

compiled, assembled, linked, loaded by Windows, and observed to exit **42**.

## 2. The acceptance

| Requirement | Result |
|---|---|
| `RAWR_NATIVE_COMPILER_STAGE1 = PASS` | PASS — 161/161 |
| C01–C08 unchanged | PASS — 161/161, no regression |
| Stage 2 gates | **21/21** |
| Source to executable | **PASS** — exit code 42, verified |
| Clean `git archive HEAD` reproduction | **PASS** — 232/232, exit 0, linker rebuilt from the export |
| All new source and test dependencies tracked | PASS — 9 files, 0 deletions |

### Merged with the shared branch

While this work was in progress the shared branch gained a **provenance gate**
(C09) and a **preprocessor gate** (C10) from another session, and that
session's commit replaced the `native_compiler` tree — which removed the Stage 2
files and the three assembler fixes from the shared branch.

The two were merged rather than chosen between. Both sets of gates are kept:

| Suite | Checks |
|---|---|
| C01–C08 — Stage 1 | 161 |
| S2 — Stage 2 | 21 |
| C09 — provenance | 6 |
| C10 — preprocessor | 44 |
| **total** | **232** |

The single conflict was in `tools/build_stage1.bat`, and the resolution runs the
Stage 2 pipeline *and* the provenance and preprocessor suites.
`tools/certification_manifest.txt` was regenerated so the provenance gate covers
the files this work added.

**The shared branch was left where it was.** Its working tree holds another
session's 401 uncommitted entries, and moving the branch under it would have
shown that session a large unrelated diff. The merge commit is a descendant of
the shared branch, so the branch can fast-forward to it when that session's
work is committed.

## 3. The three assembler defects Stage 2 found

This is the most valuable output. The Stage 1 fixtures were narrow enough that
three real defects in the certified assembler survived them. The C front end
reached them within the first hour, because ordinary C uses all three.

### A-01 — `mov r64, imm` was truncated

`mov rax, 42` came out as `48 B8 2A 00 00 00 00`. The `B8` opcode with a REX.W
prefix is `mov r64, imm64` and takes **eight** immediate bytes; only four were
written. The instruction was truncated and the bytes that followed were decoded
as part of the immediate, so the whole instruction stream after it was
misaligned.

**Fix:** a 64-bit destination with a sign-extendable value uses the `C7 /0`
form (`48 C7 C0 2A 00 00 00`); a larger value uses the full 64-bit immediate.
**Regression:** C07 now encodes the 64-bit immediate byte for byte.

### A-02 — the displacement of an `rbp` based operand was zeroed

The encoder forced `mod = 1` for an `rbp` base and then set the displacement to
zero, so `[rbp-8]` was encoded as `[rbp+0]`. The operand read or wrote the
wrong address.

**Fix:** the displacement is kept, and `mod` is chosen from its size. The SIB
form the certification suite checks is unchanged, so no certified expectation
moved.

### A-03 — the sign of a memory term was read after the term it belonged to

For `[rbp-8]` the parser consumed the `-` **after** processing the term, so the
sign was lost and the displacement became `+8`.

**Fix:** the sign is read before the term it belongs to.

**None of these three required a change to the linker's behaviour**, and none
of them was accommodated by weakening the compiler. The compiler output was
correct in all three cases; the assembler mis-encoded it.

## 4. The front end

`compilers/native_compiler/src/frontend/c_stage2.cpp` — new.

It **reuses the certified lexer** from `src/frontend/Lexer.h`. Nothing
re-implements lexing.

Supported subset:

| | |
|---|---|
| functions | with parameters, with calls, with returns |
| statements | declarations with initialisers, assignment, expression statements, `return`, `if`/`else`, `while`, blocks |
| expressions | integer literals, identifiers, calls, assignment, `+ - * / %`, `& \| ^`, `== != < > <= >=`, `&& \|\|`, `!`, unary `-`, parentheses, with C precedence |

**The frame** follows Win64: 32 bytes of shadow space, the frame size rounded
**up** to a multiple of 16 so the stack is aligned at every call, and
temporaries in frame slots rather than on the stack, so the stack pointer never
moves inside a body.

Two front-end bugs found and fixed during the work, both worth recording:

- **The comparison result was inverted.** The branch that skipped the "true"
  assignment used the comparison itself rather than its inverse, so a true
  comparison produced zero and a false one produced one.
- **A `return` inside a nested block fell through** instead of leaving the
  function. Returns now jump to a per-function epilogue.

**Function prototypes** are parsed, and a function that is called but defined
in another translation unit is declared `extern`, because the assembler cannot
write a relocation against a symbol it has never heard of.

## 5. The recovered parser was audited, and left alone

`tools/recovered_c/c_compiler_minimal.c` is the recovered minimal C compiler.
Audited: its parser knows only `return` statements and functions without
parameters, and it expected an external assembler binary at a hardcoded path
(`d:\rawrxd\native_toolchain\minimal_assembler_v5.exe`).

It is **left exactly where it was**, as a reference artifact. The front end
here is built on the *certified* lexer rather than on the recovered ad-hoc one,
which is the stronger choice and the one the instruction asked for.

What the recovered work contributed is the shape of the pipeline — front end
emits MASM, assembler turns it into a COFF object, linker produces the
executable — and the identification that the missing piece was an assembler
*command*. `tools/rawr_asm.cpp` is that command, built from the first-party
assembler.

## 6. The Stage 2 gates

`compilers/native_compiler/tests/s2_pipeline_test.cpp` — ten gates that drive
the whole chain and check the **exit code exactly**, because a pipeline that
produces a file is not a pipeline that produces a program.

| Gate | Acceptance | Result |
|---|---|---|
| S2-01 | the lexer and the parser are connected; a malformed program is rejected | PASS |
| S2-02 | integer expressions and precedence; parentheses; unary minus | PASS |
| S2-03 | local variables hold and are reassigned; two locals keep their own values | PASS |
| S2-04 | a function is called and its value returned; a call as an argument to a call | PASS |
| S2-05 | a taken branch; the else branch; a while loop accumulates | PASS |
| S2-06 | four integer arguments arrive in the right registers; a nested call keeps the frame aligned | PASS |
| S2-07 | the object is an AMD64 COFF file with its sections | PASS |
| S2-08 | the Windows executable exits with the value the program returned | PASS |
| S2-09 | two translation units link into one executable | PASS |
| S2-10 | the front end, the assembler and the linker are all present | PASS |

## 7. Clean Git archive reproduction

```
git archive HEAD compilers/native_compiler toolchain/from_scratch/phase2_linker
```

79 files exported. The native linker was **built from the exported source**
with CMake and Ninja. The suite was then built and run **from the exported
directory**:

```
C01 97/97   C02 10/10   C03  7/7   C04  7/7
C05  5/5    C06 14/14   C07 11/11   C08 10/10
S2  21/21   C09  6/6    C10 44/44
232 checks, 0 failures, exit 0
```

Evidence: `RAWR_NATIVE_COMPILER_STAGE2_001.log` (the Stage 2 tree alone, 182
checks) and `RAWR_NATIVE_COMPILER_STAGE2_001.merged_run.log` (the merged tree,
232 checks).

## 8. The external compiler, stated plainly

**MSVC 19.44 builds the certification harness and the tools.** It does not
take part in compiling the program under test: that program is compiled by the
RawrXD front end and assembler, and linked by the RawrXD linker.

**This is not compiler self-hosting.** Self-hosting remains Stage 4.

## 9. What Stage 2 does not prove

- **Not a complete C language.** The supported subset is listed in section 4.
  There are no structs, no pointers, no arrays, no floating point, no
  preprocessor, no `for`, no `switch`, no `do`, and no `goto`.
- **Not C++20.** The C++20 lexer is certified (C01), but there is no C++
  parser.
- **Not self-hosting.** See section 8.
- **The S2-06 ABI gate is a subset of the ABI.** It checks the argument
  registers, the shadow space and the stack alignment at a call. It does not
  check the full register-save convention, the x87 area, the red zone or
  structured exception handling.

## 10. The next milestone

**Stage 3 — progressive C++20 compilation.** The pieces are in place: a
certified C++20 lexer, a certified assembler, a certified COFF writer, a
certified PE linker, and a working front end that proves the pipeline. What
Stage 3 adds is the C++ parser and the widening of the IR, not new
infrastructure.

**Stage 4 — self-hosting and agentic compilation.** The RawrXD toolchain
compiles RawrXD. This needs no new components; it needs the front end to reach
the subset of C++ the project is written in, and it needs the build to stop
needing MSVC.

## 11. The process note

This work was done in a **dedicated git worktree**
(`feature/native-compiler-stage2`), separate from the shared
`preservation/source-baseline-20261021` branch, precisely because another
session was editing the same assembler and build files. That separation is
what made the work possible, and it is the change the previous review asked
for: **one active writer per shared subsystem.**

The three assembler fixes were developed against the tree in that worktree and
committed together with the front end, the tools and the certification, so
the fix and the test that proves it travel together.
