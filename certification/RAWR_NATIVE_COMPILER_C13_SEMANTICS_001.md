# RAWR_NATIVE_COMPILER_C13_SEMANTICS_001

**Date:** 2026-10-22
**Branch:** `feature/native-compiler-stage3`
**Result:** **280 checks, 0 failures, exit 0.** Clean `git archive` reproduction with the native linker rebuilt from the exported source.

---

## 1. What this milestone adds

The compiler now understands **what a program means**, not only how it is written.

```
C source
   |  C10 Preprocessor        (certified, 44 checks)
   v
token stream
   |  C11 Parser             (certified, 29 checks)
   v
AST with source spans
   |  C13 Sema                (new: this milestone)
   v
checked tree
   |  c_ast_lower.cpp         (the x64 lowering)
   v
.asm -> rawr_asm -> rawrxd_link -> Windows executable
```

The semantic layer runs **after the parser and before the lowering**. A program
that does not make sense never becomes machine code: it becomes a diagnostic
that points at the source span it is about.

## 2. The acceptance

| Requirement | Result |
|---|---|
| Existing certification preserved | PASS — C01–C08 161, C09 6, C10 44, C11 29, S2 21, S2.1 7 |
| New semantic gates | PASS — **C13 12/12** |
| No code generation when the analysis fails | PASS — gate "a program that does not make sense produces no machine code" |
| Source spans preserved through every diagnostic | PASS — every message carries line and column |
| No second parser | PASS — one parser, one tree |
| The linker unchanged | PASS |
| Clean Git archive reproduction | PASS — 280/280, exit 0, linker rebuilt from source |
| All new source tracked | PASS — 12 files, SHA-256 in the manifest |

## 3. What the semantic layer does

**Symbol tables.** The scopes nest: a file scope for the functions and the file
scope variables, a function scope for the parameters, and a block scope for the
locals. A lookup walks from the innermost scope outwards, so a local may
**shadow** an outer name — but a name may not be declared twice in the same
scope.

**Types.** Canonical representations for the integer types with their
signedness and widths, and for pointers, arrays, functions, structs and enums.
A type cannot hold itself, so the types live in an **arena that never moves
them**; a pointer into the arena stays valid for as long as the analysis does.

**Declarator chains.** Resolved from the identifier outwards, the way C reads
them:

```
int *a[10]    ->  an array of 10 pointers to int
int (*b)[10]   ->  a pointer to an array of 10 int
```

**Lvalues.** An identifier, a subscript and a member are places that can be
stored to. An assignment to anything else is reported.

**Calls.** The number of arguments is checked, and each argument is checked
against the type of its parameter.

**Returns.** Checked against the return type of the function.

**Diagnostics.** Every one carries the span of the source it is about, with the
line and the column.

## 4. Two things the C11 tree showed that the layer had to learn

### S13-01 — a function prototype is a file scope declaration

The C11 parser does **not** record `int helper(void);` as a function
declaration. It records it as a `DeclStmt` whose `VarDecl` holds a declarator
chain containing a `DeclaratorFunction`.

The layer recognises that chain, produces no code for it, and treats the name
as external. That is what makes a function declared in one translation unit
and defined in another link.

### S13-02 — `(void)` is an empty parameter list

Counting the `void` parameter made a function that takes no arguments look as
if it took one, so every call to it was reported as a wrong argument count.
Fixed in both the declarator resolution and the function definition.

## 5. The diagnostics

| Code | Message |
|---|---|
| `C1030` | the name "notdeclared" is not declared |
| `C1021` | the name "x" is declared twice in the same scope |
| `C1039` | the function "f" takes 2 arguments but 1 were given |
| `C1005` | the function "f" is defined twice |
| `C1037` | the function "nosuch" is not declared |
| `C1041` | this expression is not supported yet |
| `C1013` | a value of type X cannot be returned from a function that returns Y |

## 6. The gate

`tests/c13_semantics_test.cpp` — twelve checks:

- **Positive** — a program that makes sense is accepted and still runs.
- **Negative** — an undeclared name, a redeclaration in the same scope, a
  function defined twice, the wrong number of arguments, and a wrong return
  type, each with its diagnostic code.
- **Scope** — a nested scope may shadow an outer name; a function may not be
  defined twice.
- **Type** — a matching assignment is accepted; a declarator chain is read
  without crashing.
- **No code for a bad program** — the front end produces no assembly at all.
- **Determinism** — the same source produces the same diagnostics every time.
- **Cross translation unit** — a function declared in one unit and defined in
  another.

## 7. What is not supported — explicitly

Every one of these produces a **diagnostic**, never invalid machine code.

**Language** — pointers and pointer arithmetic · arrays and subscripting ·
structs, unions and member access · enums · typedefs · `switch`, `case`,
`default` · `break`, `continue`, `goto` · labels · floating point · variadic
functions · `sizeof` · compound assignment · shifts · the conditional operator ·
string literals · casts · storage class specifiers · file scope variables ·
function pointers.

**ABI** — more than four arguments (a fifth would go on the stack) · the
caller-saved registers are never saved and never restored, because the lowering
uses only volatile registers · the stack arguments of a variadic call · unwind
information.

**Not claimed:** complete C17, complete C++20, self-hosting.

## 8. The next milestone — the shared typed IR

The types this layer introduced are the raw material for the IR that C and the
future C++20 front end will share. The contract:

```
IRModule
  functions: IRFunction[]
IRFunction
  name, return type, parameters, locals
  blocks: IRBlock[]        a control flow graph, not a tree
IRBlock
  instructions: IRInst[]
  terminator: branch | conditional branch | return
IRInst
  an operation on typed values: add, sub, load, store, call, phi
IRValue
  a type and a definition
```

The lowering then reads the IR instead of the syntax tree, which is what lets
a C++ front end produce the same IR as C.

Three things follow from that, in order:

1. **The IR and the CFG builder**, with the lowering reading them.
2. **The C language gaps above**, in the order the gates need them — the
   pointer and array work is what unblocks the aggregate types.
3. **Progressive C++20** — namespaces, references, classes, constructors and
   overload resolution — on the same IR.

The consolidation is the point: two parsers with two sets of language semantics
would have produced exactly the conflicts this removes.
