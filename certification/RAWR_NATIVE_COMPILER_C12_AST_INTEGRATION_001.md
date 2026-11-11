# RAWR_NATIVE_COMPILER_C12_AST_INTEGRATION_001

**Date:** 2026-10-22
**Branch:** `feature/native-compiler-stage3`
**Result:** **268 checks, 0 failures, exit 0.** Clean `git archive` reproduction with the native linker rebuilt from the exported source.

---

## 1. What this milestone does

`rawr_c` now compiles through the **certified C10 preprocessor and the certified
C11 parser**. The tree they produce is lowered to x64 by the existing certified
backend. The compiler has one front end, not two.

```
C source
   |  C10 Preprocessor                     (certified, 44 checks)
   v
token stream
   |  C11 Parser                          (certified, 29 checks)
   v
AST with source spans
   |  src/frontend/c_ast_lower.cpp        (new: the lowering)
   v
.asm
   |  rawr_asm -> rawrxd_link             (certified)
   v
Windows executable
```

The older front end in `src/frontend/c_stage2.cpp` is **kept for regression
comparison and is not the production path**.

## 2. The acceptance

| Requirement | Result |
|---|---|
| `RAWR_NATIVE_COMPILER_STAGE1 = PASS` | PASS |
| Existing certification preserved | PASS — C01–C08 161, C09 6, C10 44, C11 29 |
| New integration gates | PASS — S2 21, **S2.1 exit 87: 7** |
| `rawr_c` uses C10 and C11 | PASS |
| Incorrect source produces diagnostics, never invalid machine code | PASS |
| Clean Git archive reproduction | PASS — 268/268, exit 0, linker rebuilt from source |
| All new source tracked | PASS — 15 files, SHA-256 in the manifest |

## 3. Two more defects the integration exposed

The C11 path reached constructs the old front end never produced, and two more
real defects appeared. Both are fixed and both now have coverage.

### A-04 — `idiv` did not emit a REX prefix for the extended registers

`idiv r10` was encoded as **`idiv rdx`**, because the `rm` field of the ModRM
byte only holds the low three bits and no REX was emitted. The `imul` path
already emitted it; `idiv` did not.

This was invisible until the lowering moved its scratch register to `r10`.

**Fix:** the REX prefix is emitted, as `imul` already did.

### A-05 — the lowering used a callee-saved register as its scratch

`rbx` is **callee saved** in Win64: a function that clobbered it broke the
rule that a callee preserves it. The lowering used `rbx` for the second
operand of every binary operation.

**Fix:** `r10` is used instead. `r10` is **volatile**, so the caller may not
rely on it across a call, and the prologue is unchanged — no register has to be
saved and restored.

## 4. Two things the C11 tree showed that the old front end did not

- **A function prototype is a file scope declaration**, not a `FunctionDecl`. The
  C11 parser records `int helper(void);` as a `DeclStmt` whose `VarDecl` holds
  a declarator chain containing a `DeclaratorFunction`. The lowering recognises
  that chain, produces no code for it, and treats the function as external — so
  two translation units link.
- **The parser accepts an empty return.** `return ;` parses. The lowering
  checks that a function which returns a value actually returns one, and reports
  a diagnostic when it does not. This is what makes the S2-01 gate meaningful
  again: the rejection is now a *semantic* check, not a parser accident.

## 5. The AST to backend mapping

Every C11 node the lowering understands, and what it becomes:

| C11 AST | x64 lowering |
|---|---|
| `TranslationUnit` | the file scope: each function becomes a global label; a file scope declaration is a prototype or a diagnostic |
| `FunctionDecl` | `global <name>`, the prologue, the parameters moved into their slots, the body, the epilogue |
| `ParamDecl` | the parameter's frame slot, filled from the argument register it arrived in |
| `VarDecl` (local) | the frame slot, and the initialiser stored into it |
| `DeclStmt` | the local declarations, in order |
| `CompoundStmt` | the statements, in order |
| `ExprStmt` | the expression, for its effect |
| `IfStmt` | `cmp rax,0` · `je else` · the body · `jmp end` · else: the else body · `end:` |
| `WhileStmt` | `top:` the condition · `je end` · the body · `jmp top` · `end:` |
| `DoStmt` | `top:` the body · the condition · `jne top` · `end:` |
| `ForStmt` | the initialiser · `top:` the condition · `je end` · the body · the step · `jmp top` · `end:` |
| `ReturnStmt` | the value into `rax`; for `main` the call to `ExitProcess` with the value in `ecx`; otherwise a jump to the epilogue |
| `IntegerLiteral` / `CharLiteral` / `BoolLiteral` | `mov rax, <immediate>` |
| `IdentifierExpr` | `mov rax, [rbp - <slot>]` |
| `BinaryExpr` | the left operand into a frame slot, the right into `rax`, the operand into `r10`, the operation |
| `AssignExpr` | the right side into `rax`, then stored into the slot of the left |
| `UnaryExpr` | `!` is a compare and two branches; `-` is `neg` |
| `CallExpr` | the arguments into frame slots, then into `rcx`, `rdx`, `r8`, `r9`, then the call |
| `ErrorExpr` / `ErrorStmt` | a diagnostic from the parser; the lowering never sees one |

The frame is the certified one: 32 bytes of shadow space, the frame size a
multiple of 16 so the stack is aligned at every call, and the temporaries in
frame slots rather than on the stack. A function with no locals, no parameters
and no temporaries needs no frame pointer, so it reserves the shadow space and
the alignment only — which is what makes the canonical program encode to
exactly the documented bytes:

```
48 83 EC 28 B9 57 00 00 00 E8 00 00 00 00 48 83 C4 28 C3
```

## 6. The exit 87 certification

`tests/s2_1_exit87_test.cpp`. The same pipeline, asked for a different value,
so a hardcoded 42 cannot pass it:

| Program | Exit |
|---|---|
| `return 87;` | 87 |
| `return 80 + 7;` | 87 |
| `return 100 - 13;` | 87 |
| `int x = 29; return x * 3;` | 87 |
| `int x = 174; return x / 2;` | 87 |

Plus the byte-exact check of the canonical encoding, and a program the front
end has to reject.

## 7. What is **not** supported

Every one of these produces a **diagnostic**, never invalid machine code.

**Language** — pointers and pointer arithmetic · arrays and subscripting ·
structs, unions and member access · enums · typedefs · `switch`, `case`,
`default` · `break`, `continue`, `goto` · labels · floating point · variadic
functions · `sizeof` · compound assignment · shifts · the conditional operator ·
string literals · casts · storage class specifiers · file scope variables ·
function pointers · nested scopes with the same name.

**ABI** — arguments are passed in the four integer registers only, so a fifth
argument would go on the stack and that is not implemented · the caller saved
registers are never saved and never restored, because the lowering now uses only
volatile registers · the stack arguments of a variadic call are not set up ·
there is no unwind information.

**Also not claimed:** complete C17, complete C++20, self-hosting.

## 8. The next milestone

**The C++ front end and the typed IR.** The pieces are now in place: a
preprocessor, a C11 parser, a tree with source spans, a certified x64 backend,
a certified assembler, a certified COFF writer, a certified PE linker, and a
front end that produces running Windows executables from C.

Stage 3 continues with:

1. **Semantic analysis** — name resolution, basic types, the lvalue and rvalue
   distinction, and the return check, all producing diagnostics that point at the
   source span.
2. **A typed IR** the C and C++ front ends share, with the lowering reading it
   instead of the syntax tree.
3. **The C language gaps above**, in the order the gates need them.
4. **Progressive C++20** — namespaces, references, classes, constructors and
   overload resolution — on the same IR.

The consolidation is done, which was the point: two parsers with two sets of
language semantics would have produced exactly the conflicts this removes.
