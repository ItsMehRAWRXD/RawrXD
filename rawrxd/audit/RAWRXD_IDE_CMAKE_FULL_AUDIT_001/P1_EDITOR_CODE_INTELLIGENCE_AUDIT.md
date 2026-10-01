# IDE P1 — Editor / Code Intelligence: Capability Audit

    SCOPE     = Editor and code-intelligence capability
    METHOD    = Repo-wide symbol census, NOT a win32app/*.cpp scan
    DATE      = 2026-10-01
    HEAD      = 8623e86a5 .. 3777093876
    FILES_SCANNED = 3525 (.cpp/.hpp/.h, excluding build/, 3rdparty/, _remote_extract/)

**This audit corrects the record.** Several capabilities previously called
missing are not missing — they simply do not live in `win32app/`. More
importantly, three capabilities DO exist and are *registered as working*, and
two of them **report success without doing the work**. That is a worse state
than absence, and it is recorded as such below.

---

## 1. Refactoring-chain coverage

| # | Capability | Real home | State |
|---|---|---|---|
| 1 | definition | `RepositoryIntelligence::GoToDefinition` / `GoToDeclaration`; `auto_feature_registry.cpp:2509` handler | index **real**; registry handler **FALSE PASS** (§2) |
| 2 | references | `RepositoryIntelligence::FindReferences` / `FindReferencesAt` / `FindCallers` / `FindCallees` | **implemented** |
| 3 | rename | `auto_feature_registry.cpp:2563` handler | **FALSE PASS** (§3) |
| 4 | symbol search | `RepositoryIntelligence::SearchSymbols`, `SearchIndex::FuzzySearch` | **implemented** |
| 5 | workspace symbols | `RepositoryIntelligence::SearchByType`, `FindSymbolsByName`, `GetAllSymbols` | **implemented** (no `WorkspaceSymbol` API name — capability present, name absent) |
| 6 | diagnostics | `include/vscode_extension_api.h` provider interface (`:1022`, `:1118`) | interface present; **runtime unproven** |
| 7 | code actions | `VSCodeCodeActionProvider` (`vscode_extension_api.h:1119`) | interface present; **runtime unproven** |
| 8 | format | `FormatCode` appears only in `ChatTemplate.cpp` (unrelated) | **no editor formatter found** |
| 9 | extract function | — | **CONFIRMED GENUINE GAP** (§4) |

Supporting surfaces confirmed real, not stubs: command palette
(`command_registry.cpp`, 31 refs), Ctrl+P / quick-open
(`command_registry.h:134` `workbench.action.quickOpen`, `:135` `gotoSymbol`),
ghost text (`Win32IDE_GhostText.cpp` + `MonacoCoreEngine.cpp`), clip (4),
undo (13), selection (46) in `Win32IDE_EditorEngine.cpp`.

### Why a `win32app/*.cpp` scan produced wrong answers

`Win32IDE_EditorEngine.cpp` (38756 bytes) contains **zero** occurrences of
`Rename`, `Format`, `Diagnostic`, `Definition`, `Reference`, `Palette`, or
`Fuzzy`. A scan of that file alone therefore reports all seven as absent. They
are implemented elsewhere — `src/repo/RepositoryIntelligence.*`,
`src/core/auto_feature_registry.cpp`, `src/core/semantic_code_intelligence.*`,
`src/core/command_registry.*`. **Absence from `win32app/` is not absence from
the product.**

---

## 2. `handleLspGotoDefinition` — reports success on failure

`src/core/auto_feature_registry.cpp:2509`

```cpp
snprintf(buf, sizeof(buf), "[LSP] Symbol '%s' not found in index.\n", ctx.args);
ctx.output(buf);                                   // line 2521-2522: told the user it FAILED
} else {
    ctx.output("[LSP] Navigating to definition of symbol at cursor...\n");
}
return CommandResult::ok("lsp.gotoDefinition");    // line 2526: returns SUCCESS anyway
```

Two defects:

1. **A miss returns `ok`.** The handler prints "not found" and then returns
   `CommandResult::ok`. Any caller or receipt treating the return code as the
   authority records a pass for a failed lookup.
2. **The no-argument branch is a stub.** With no args it prints "Navigating to
   definition of symbol at cursor…" and returns `ok` without reading a cursor
   position or resolving anything. That message asserts an action that never
   occurred.

Separately, `sym.name == ctx.args` compares a `std::string` against the whole
`const char*` argument string, so any trailing text makes the match fail.

The index underneath is real (`RepositoryIntelligence::GoToDefinition`), so this
is a handler defect, not a missing capability.

---

## 3. `handleLspRenameSymbol` — renames nothing, reports success

`src/core/auto_feature_registry.cpp:2563`

```cpp
auto& provider = HotpatchSymbolProvider::instance();
auto symbols = provider.getAllSymbols();
bool found = false;
for (auto& sym : symbols) { if (sym.name == oldName) { found = true; break; } }
if (found) {
    provider.rebuildIndex();
    snprintf(buf, sizeof(buf), "[LSP] Renamed '%s' -> '%s' (index rebuilt)\n", oldName, newName);
}
...
return found ? CommandResult::ok("lsp.renameSymbol") : CommandResult::error("Symbol not found", -1);
```

**No file is opened, no text is rewritten, no edit is recorded.** The handler
confirms the symbol exists, rebuilds the index, and prints "Renamed". The
message is a false claim about an effect that did not occur, and the return code
is `ok`.

This is the precise pattern the project's own rules forbid — a simulated success
on a real code path. It is more dangerous than an unimplemented feature because
a user renaming a symbol through this path would be told it worked.

---

## 4. Extract Function / Extract Method — confirmed genuine gap

Zero results repo-wide for all five plausible spellings:

```ini
ExtractFunction          = 0
ExtractMethod            = 0
ExtractFunctionCommand   = 0
extract_function         = 0
ExtractToFunction        = 0
```

This is the one capability in the chain with **no implementation of any kind** —
not even a false-pass stub. It is correctly deferred: per the P1 sequencing, it
becomes a real implementation task only after P0 closure.

---

## 5. Format — no editor formatter found

`FormatCode` appears only in `ChatTemplate.cpp`, which is a chat-prompt concern
and unrelated to editor formatting. `FormatDocument`, `FormatRange`,
`formatSelection`, `clang_format` all return zero. `Indent` has 137 hits, which
is bracket/completion indentation logic, not a document formatter.

Classification: **no editor formatter is implemented.** Unlike Extract Function,
this one was not on the stated confirmed-gap list, so it is reported here as a
new finding rather than folded into the existing gap.

---

## 6. Recommended order

1. **P0 first** — establish one IDE build authority (see
   `IDE_POSITION_AND_NEXT_STEPS.md` §5). Certification is meaningless while a
   target subtree is unreachable and `ctest` enumerates zero tests.
2. **Fix the two false passes** (§2, §3) before any runtime proof. A capability
   that reports success without acting will produce a green runtime receipt that
   certifies nothing.
3. **Runtime-proof the real ones** (§1 rows 2, 4, 5) — these need execution
   evidence, not source presence.
4. **Then** implement Extract Function (§4) and the editor formatter (§5).

## 7. Authority — P1

```ini
P1_CENSUS_METHOD                  = REPO_WIDE (win32app-only scan corrected)
FILES_SCANNED                     = 3525

DEFINITION_INDEX                  = IMPLEMENTED
REFERENCES                        = IMPLEMENTED
RENAME_INDEX                      = IMPLEMENTED
RENAME_REGISTRY_HANDLER           = FALSE_PASS_NO_EDIT
DEFINITION_REGISTRY_HANDLER       = FALSE_PASS_ON_MISS
SYMBOL_SEARCH                     = IMPLEMENTED
WORKSPACE_SYMBOLS                 = IMPLEMENTED
DIAGNOSTICS                       = INTERFACE_ONLY_RUNTIME_UNPROVEN
CODE_ACTIONS                      = INTERFACE_ONLY_RUNTIME_UNPROVEN
FORMAT                            = NOT_FOUND
EXTRACT_FUNCTION                  = CONFIRMED_GAP_ABSENT
GHOST_TEXT                        = IMPLEMENTED
COMMAND_PALETTE                   = IMPLEMENTED
QUICK_OPEN                        = IMPLEMENTED

FALSE_PASS_HANDLERS_FOUND         = 2
P1_VERDICT                        = NOT_CERTIFIED
P1_BLOCKED_ON                     = P0 (IDE build authority) + false-pass repair
```