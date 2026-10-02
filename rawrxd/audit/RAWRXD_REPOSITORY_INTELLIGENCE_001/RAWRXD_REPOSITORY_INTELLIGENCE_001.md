# RAWRXD_REPOSITORY_INTELLIGENCE_001

    GATE                    = RAWRXD_REPOSITORY_INTELLIGENCE_001
    SUBJECT                 = Semantic repository intelligence (ladder item 6, P1)
    VERDICT                 = PASS
    VERDICT_DERIVED_FROM    = 14 measured checks, 14 passed, 0 failed
    MEASURED_AGAINST        = F:\~dev\rawrxd, the whole repository
    RECEIPT_MACHINE         = audit/RAWRXD_REPOSITORY_INTELLIGENCE_001/RECEIPT.txt
    RECEIPT_PRODUCED_BY     = repo_intelligence_cert (a real executable)
    SOURCE_OF_TRUTH         = filesystem walk only. No git. No glob assumption.

---

## 1. What was wrong, measured rather than asserted

The user's report â€” "repeatedly searches only `win32app/*.cpp` and declares
features absent" â€” is not one bad script. It is a class, and the class has a
concrete instance in the shipping product.

The worst instance is the IDE's own language-server workspace, at
`src/core/ssot_handlers.cpp:1366` before this change:

```cpp
static std::vector<std::string> collectDefaultLspSearchFiles()
{
    std::vector<std::string> files;
    files.reserve(1024);
    const std::array<const char*, 4> roots = {"src", "include", "tests", "test"};
    for (const char* root : roots)
    {
        collectLspSearchFilesRecursive(root, files, 1600);
        if (files.size() >= 1600)
            break;
    }
    return files;
}
```

Four hardcoded directory names. A 1600-file cap against a repository the
project's own audit measured at **1968 implementation files**
(`audit/RAWRXD_IDE_CMAKE_FULL_AUDIT_001/RECEIPT.md:153`). Because
`collectLspSearchFilesRecursive` recursed in alphabetical order and broke at the
cap, the truncation landed on the **tail of `src/`** â€” `reverse_engineering`,
`runtime`, `serve`, `soloide`, `sovereign`, `tokenizer`, `win32app`. And nothing
anywhere recorded that a search had been cut short, so a feature living past the
cap was indistinguishable from a feature that did not exist.

Reconstructing that walk and running it here, against this repository, today:

```ini
LEGACY_SCOPE_ROOTS                = 4  (src, include, tests, test)
LEGACY_SCOPE_CAP                  = 1600
LEGACY_SCOPE_FILES                = 1600
LEGACY_SCOPE_TRUNCATED            = 1
LEGACY_SCOPE_FILES_IF_UNCAPPED    = 3843
LEGACY_SCOPE_FILES_LOST_TO_CAP    = 2243
UNIVERSE_FILES                    = 4607
FILES_VISIBLE_REPO_WIDE_BUT_INVISIBLE_TO_LEGACY_SCOPE = 3009
FILES_OUTSIDE_ALL_FOUR_LEGACY_ROOTS                   = 3009
```

**2243 source files were invisible because of the cap. 3009 were invisible
because of the directory list.** The two defects are independent; removing the
cap alone would still have hidden every file outside those four names â€”
`3rdparty/`, `rguf_source/`, `win32ide_strict/`, `B01*/build/`, `tools/`,
`scripts/`, `evidence/`, `receipts/`, `audit/`.

### The same false absence, reproduced end to end

The harness builds a universe restricted to `src/win32app` â€” the scope the user
described â€” and asks it where `runAudit` is:

```ini
NARROW_SCOPE_FILE_COUNT      = 42
NARROW_SCOPE_FINDING         = runAudit NOT FOUND -> would have been reported ABSENT
REPO_WIDE_FINDING            = runAudit found at src/agentmodes/RawrAuditAuthority.cpp
FALSE_ABSENCE_DEMONSTRATED   = 1
```

That is the defect in one line: a scoped search returns an empty result, and the
empty result is read as an absence.

### Ten prior "absent" claims, re-checked repo-wide

Capability names that earlier audits of this repository recorded as absent or
gated, asked of the whole-repository index:

```ini
IDECore_Shutdown           -> src/win32app/Win32IDE_Core.cpp:74
RECEIPT_IMMUTABILITY       -> src/deep2/ReceiptAuthority.cpp:65
SINGLE_WRITER              -> src/agentmodes/WriterLeaseAuthority.cpp:502
PRODUCTION_PROFILER        -> src/deep2/ProductionProfiler.hpp:87
NVME_STREAM                -> src/deep2/NVMeStream.cpp:22
BP16_STREAMER              -> src/core/gold_link_closure.cpp:1055
COMPRESSED_KV_CACHE        -> src/deep2/CompressedKVCache.cpp:73
MARS_CONTROLLER            -> src/deep2/mars/MARSController.cpp:7

ABSENCE_CLAIMS_RESOLVED_REPO_WIDE   = 8
ABSENCE_CLAIMS_UNRESOLVED_REPO_WIDE = 2
```

Eight of ten resolve to real definitions with `file:line`. `IDECore_Shutdown` is
the one the prior audit explicitly reported as having zero callers; it is a
definition at `src/win32app/Win32IDE_Core.cpp:74`. The two that do not resolve
are recorded as genuinely unresolved, and â€” this is the point â€” the claim is
*allowed*, because the universe covered the whole repository.

---

## 2. What was built

```text
src/repointel/ScopeTree.hpp / .cpp                structural scope analyzer
src/repointel/RepositoryUniverse.hpp / .cpp       whole-repository manifest
src/repointel/RepositoryIntelligence.hpp / .cpp   index, graphs, search, ranking
src/repointel/RepoIntelCli.hpp / .cpp             the `rawr repo` surface
tools/repo_intelligence_cert.cpp                  the measurement harness
```

Three properties are structural, not conventions.

**1. The root is resolved from the filesystem.** `resolveRepositoryRoot()` walks
up from the starting directory to the nearest ancestor carrying a
`CMakeLists.txt`. There is no list of directory names anywhere in the walk.

**2. Every excluded tree is still enumerated, and reported.** The walk descends
into pruned `build*` directories solely to count what is under them, so a
narrowed result always carries the cost of the narrowing:

```ini
PRUNED_DIRS          = 63
PRUNED_FILES_BELOW   = 17706
PRUNED_BYTES_BELOW   = 4879885185
```

A reader can always distinguish *found nothing there* from *never looked*.

**3. An absence claim is refused from a narrowed scope.** This is the part an
audit convention cannot supply.

```ini
NARROW_SCOPE_CLAIM_ALLOWED = 0
NARROW_SCOPE_REFUSAL = SCOPE_NARROWED: this universe was not the whole
                        repository, so no absence may be claimed from it.
                        scopeLabel=win32app-only, the legacy audit scope
FULL_SCOPE_CLAIM_ALLOWED  = 1
FULL_SCOPE_UNIVERSE_FILES = 4607
```

A narrowed universe cannot produce a false absence because it cannot produce an
absence claim at all. `claimAbsence()` also refuses when the root is missing or
when `maxFiles` truncated the walk.

---

## 3. Capability-by-capability, with the measurement

| Capability | Result | Measured |
|---|---|---|
| Incremental repository indexing | PASS | 1 of 4607 files re-parsed, 9212 reused, 795 ms vs 4917 ms full = **6.18x** |
| Changed-file invalidation | PASS | `modified=1`, `hashVerified=1`; the edited file named in the receipt |
| Persistent index | PASS | 72,401,959 bytes written, reloaded, **all reload comparisons identical** |
| Deterministic index rebuild | PASS | two payloads byte-identical: `7bcc0c379445764f` == `7bcc0c379445764f` |
| Symbol / reference graph | PASS | 9/9 probes resolved to the expected `file:line`, 0 wrong files |
| Cross-file reasoning | PASS | `runAudit` caller found in a different file; multi-hop depth 2 across 3 files |
| AST-aware chunking | PASS | 49,007 scope-accurate chunks (see the honesty note in Â§4) |
| Dependency traversal | PASS | 14,263 include edges, 2,664 resolved, transitive closure verified |
| Context ranking | PASS | 12 ranked chunks, monotonic and reproducible across two calls |
| Repository-scale search | PASS | 144,120 tokens, 769,021 postings, over 4,607 files / 131 MB |
| Very-large-repository behaviour | PASS | see Â§5 |

### Structural analysis, not text splitting

One lexical pass per file yields the scope tree, the symbol table, the call
edges, the include edges, and each scope's identifier set. Stage 1 tracks line
comments, block comments, string literals, character literals (guarding against
digit separators like `1'000`), raw strings with encoding prefixes
(`R"delim(...)delim"`, `u8R`), and preprocessor directives including backslash
continuations â€” so a brace inside any of them never becomes a token and cannot
open a scope. Stage 2 walks statement segments delimited by `;` `{` `}` and
classifies each by its head token: namespace, class/struct/union body, enum
body, function body, or anonymous block.

The chunk census shows it is not emitting one kind of node and calling it a
graph. (Figures are from the run in `RECEIPT.txt`; the repository is under
active edit, so a later run will differ. The receipt is the authority.)

```ini
CHUNK_KIND_FUNCTION  = 39502
CHUNK_KIND_STRUCT    = 4044
CHUNK_KIND_NAMESPACE = 3136
CHUNK_KIND_ENUM      = 778
CHUNK_KIND_CLASS     = 1468
CHUNK_KIND_UNION     = 79

SYMBOL_KIND_FUNCTION     = 39460
SYMBOL_KIND_VARIABLE     = 37384
SYMBOL_KIND_MACRO        = 8856
SYMBOL_KIND_ENUM_CONSTANT= 7457
SYMBOL_KIND_FIELD        = 4054
SYMBOL_KIND_STRUCT       = 3970
SYMBOL_KIND_NAMESPACE    = 2864
SYMBOL_KIND_TYPE_ALIAS   = 2262
SYMBOL_KIND_CLASS        = 1465
SYMBOL_KIND_ENUM         = 751
SYMBOL_KIND_METHOD       = 42
SYMBOL_KIND_UNION        = 4
```

`SYMBOL_KIND_METHOD = 42` against `SYMBOL_KIND_CLASS = 1465` is worth stating
rather than hiding: a method is only recognised when its declarator is preceded
by a `Type::` qualifier or the enclosing scope is a class body. Most classes in
this repository declare members as free functions or through `struct` scopes
where the trailing-`::` form does not appear, so the method count is low. It is
a measurement of the analyzer's rules, not a statement about the codebase.

---

## 4. What this is not

Stated plainly, because the alternative is a receipt that overstates.

```ini
CHUNKER                  = SCOPE_TREE_STRUCTURAL
FULL_CPP_AST             = 0
TREE_SITTER_AVAILABLE    = 0
LIBCLANG_AVAILABLE       = 0
FIELD_DETECTION_HEURISTIC= 1
SYMBOL_RESOLUTION        = NAME_BASED_NO_OVERLOAD_DISAMBIGUATION
```

- **Not a semantic C++ parse.** No template instantiation, no overload
  resolution, no type checking. Chunks are scope-accurate, not semantically
  typed.
- **Field detection is a heuristic** and will produce false positives.
- **Symbol resolution is by name.** The multi-hop traversal found
  `analyzeSource` reaching `include/pdb_reference_provider.h:149` â€” a real
  function of the same name in a different file. That is correct behaviour for
  a name-based index and is labelled rather than hidden.
- **`INCLUDE_EDGES_UNRESOLVED = 11599`** of 14263. Most are system headers
  (`<windows.h>`, `<cstdint>`) that no repository can resolve. Resolution of
  angled includes falls back to shallowest-basename matching, which is
  deterministic but can pick a sibling when many headers share a name.
- **`git` is deliberately unused.** `git ls-files` was the *cause* of a false
  absence in this repository: `.gitignore:8` is an unanchored `build*/`, which
  excludes `src/build/BuildIntelligence.cpp` and six `B01*/build/*.cpp` files
  that `CMakeLists.txt` names as build inputs. 26 source directories are
  untracked entirely. The universe is therefore filesystem-only.

### One further finding, stated because it was found

`src/core/ssot_handlers.cpp` â€” the file holding the narrow-scope defect â€” **does
not compile today**. Its first include is `../../native_gguf_loader.h`, which
does not exist in the repository; `CMakeLists.txt:5814` records the file as
`EXCLUDED: missing native_gguf_loader.h`. So:

```ini
LSP_SCOPE_FIX_APPLIED_TO_SOURCE = 1
LSP_SCOPE_FIX_RUNTIME_EVIDENCE  = 0
LSP_SCOPE_FIX_BLOCKED_BY        = ssot_handlers.cpp has a missing first include
```

The replacement was verified by extracting it verbatim into a standalone
harness against the same header:

```ini
LSP_ROOT                     = F:\~dev\rawrxd
LSP_UNIVERSE_FILES           = 4058      (was: capped at 1600)
LSP_FILES_SEEN               = 7192
LSP_PRUNED_DIRS              = 62
LSP_PRUNED_FILES_BELOW       = 17700
LSP_TRUNCATED                = 0         (was: silently truncated)
LSP_FILES_UNDER_win32app     = 53        (invisible to the old walk)
REPLACEMENT_COVERS_MORE_THAN_THE_OLD_CAP = 1
REPLACEMENT_IS_CACHED                    = 1
VERDICT                      = PASS
```

Restoring that translation unit is a separate blocker and is not claimed here.

---

## 5. Conflicting and hollow implementations found in the same subsystem

Found by a repo-wide census, then **verified by reading the cited lines**
rather than relayed. These are the pre-existing implementations of the same
capabilities. None is the live path; each is recorded so the next reader knows
what exists and why it was not used.

### 5.1 A false-success surface already linked into two shipping targets — FIXED

`src/core/semantic_code_intelligence.cpp` (924 lines) implements
`goToDefinition`, `findAllReferences`, `getCallersOf`, `getCallChain`,
`getCompletions`, `getHoverInfo`, `rebuildIndex`, `saveIndex`/`loadIndex`. It is
bound to two targets — `CMakeLists.txt:2928` and `:5984`. Its indexer did
nothing and reported success anyway:

```cpp
// src/core/semantic_code_intelligence.cpp:915-924, as it was
void SemanticCodeIntelligence::buildFileIndex(const std::string& filePath) {
    // Called with lock held
    // In production, this would parse the file using a language-specific parser
    // For now, mark the file as indexed
    m_stats.filesIndexed.fetch_add(1);
    if (m_progressCb) m_progressCb(filePath.c_str(), 100, m_progressData);
}

// :668-673, as it was
PatchResult SemanticCodeIntelligence::indexFile(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(m_mutex);
    buildFileIndex(filePath);
    m_stats.filesIndexed.fetch_add(1);
    return PatchResult::ok("File indexed");
}
```

That is worse than an ordinary stub: it incremented `filesIndexed` **and fired a
100% completion callback** for work it never performed, and answered `ok` for a
path that did not exist. Every query above reads state only that function wrote,
so all of them returned empty forever.

**Now fixed, and proven fixed.** `buildFileIndex` parses with the same certified
`repointel::analyzeSource`, returns `bool`, and `indexFile` propagates it. The
analyzer sources were added to both owning targets. Measured by
`semantic_code_intelligence_cert`, which indexes real files from this
repository and then asks the queries real questions:

```ini
FILES_INDEXED                 = 6
STAT_totalSymbols             = 254
STAT_totalScopes              = 147
STAT_totalReferences          = 259
GOTO_DEFINITION_PROBES        = 5
GOTO_DEFINITION_RESOLVED      = 5   (scanSourceTree:334, writeAuditReceipt:418,
                                      runAudit:465, buildUniverse:300,
                                      analyzeSource:981 — all real file:line)
REFERENCES_OF_runAudit        = 3
CALLERS_OF_runAudit           = 1   (RawrModesCli.cpp — cross-file, correct)
CALLEES_OF_runAudit           = 2
CALL_CHAIN_DEPTH_OF_runAudit  = 14
COMPLETIONS_prefix_scan       = 4   (incl. scanSourceTree)
SEARCH_Audit                  = 20
SYMBOLS_IN_FIRST_FILE         = 34
INDEX_MISSING_FILE_SUCCESS    = 0   ("File not readable: ...")

CHECKS_TOTAL=11  CHECKS_PASSED=11  CHECKS_FAILED=0
VERDICT=PASS  SEMANTIC_SURFACE=LIVE
```

Two side effects worth recording. `filesIndexed` for the same six files dropped
from **12 to 6** — the old `indexFile` double-counted, once in itself and once
in `buildFileIndex`. And the missing-file case, which previously answered
`PatchResult::ok("File indexed")` for a path that does not exist, now returns an
error; that check is in the harness so the lie cannot come back quietly.

Fields the analyzer does not resolve are left at their defaults — `typeId`,
`baseTypes`, `documentation` and `signature` stay zero rather than being filled
with a plausible-looking guess.

### 5.2 Two "embeddings" that are hashes, and a model that is loaded by `reinterpret_cast`

```cpp
// src/core/minigw_runtime_symbol_batch7.cpp:344-348
EmbedResult EmbeddingEngine::loadModel(const EmbeddingModelConfig& config) {
    ...
    modelLoaded_ = true;
    modelHandle_ = reinterpret_cast<void*>(0x1);
```

The same pattern appears again at `:404-408` for `VisionEncoder::loadModel`.
`makeEmbedding` in `src/core/codebase_indexer.cpp:81` is a sin-wave character
hash; `EmbeddingIndex.cpp:44` is a hash-bag-of-words. The file also defines a
second `HNSWIndex::~HNSWIndex()` at `:337`, duplicating
`src/core/vector_index.cpp:209`.

```ini
MINIGW_BATCH7_IN_ANY_BUILD_TARGET = 0
HARDCODE_MODEL_LOADED_TRUE       = 2 occurrences
DUPLICATE_HNSW_DESTRUCTOR        = 1 (dead: file is in no target)
```

Dead code today, so nothing false is currently being reported. It is a loaded
gun: `modelLoaded_ = true` with `modelHandle_ = 0x1` is a hardcoded pass, and
`AGENTS.md` names that pattern explicitly.

### 5.3 A class declared in a header that no implementation exists for

`src/repo/FileIndex.hpp` declares `RawrXD::IDE::FileIndex` with a nested
`class Impl;`. `src/repo/FileIndex.cpp` implements `RawrXD::Repo::FileIndexManager::Impl`
â€” different namespace, different class. Any construction of `RawrXD::IDE::FileIndex`
is a link error. Silent only because nothing constructs it.

### 5.4 A semantic index the IDE declares and does not have

`CMakeLists.txt:5520` lists `src/win32app/Win32IDE_SemanticIndex.cpp` with the
comment "REAL: Semantic code intelligence (509 lines)". The file does not exist
on disk. `src/lsp/RawrXD_LSPServer.cpp`, `hotpatch_symbol_provider.cpp`,
`lsp_hotpatch_bridge.cpp` and `gguf_diagnostic_provider.cpp` are likewise
declared and absent.

### 5.5 A recursive lock in dead code

`src/repo/IncludeGraph.cpp:74` takes a `unique_lock` on a non-recursive
`shared_mutex` and then calls `GetOrCreateNode` (`:61`), which takes it again.
Deadlock on any concurrent use. Dead code today.

### 5.6 The prior receipts never claimed this worked

```ini
receipts/RAWRXD_CODE_INDEX_001      VERDICT=PENDING, all REQ_* PENDING, empty EVIDENCE
receipts/RAWRXD_CONTEXT_ENGINE_001  VERDICT=PENDING, all REQ_* PENDING, empty EVIDENCE
```

Nothing to retract. The one honest prior assessment is
`audit/RAWRXD_IDE_CMAKE_FULL_AUDIT_001/_receipt_tail.txt:151-157`, which records
symbol extraction, definition/reference lookup and semantic search as
`PRESENT-UNBOUND` and incremental invalidation as `STUB`. That census was right.
This work makes those capabilities reachable, and adds the scope guard that
turns `PRESENT-UNBOUND` from a silent condition into a refused claim.

---

## 6. Very-large-repository behaviour

```ini
FILES_INDEXED            = 4607
BYTES_INDEXED            = 131,284,440   (131 MB of source)
LINES_INDEXED            = 2,613,273
FILES_SEEN_ALL_TYPES     = 7227
UNIVERSE_BYTES_SEEN      = 2,601,518,085 (2.6 GB, including what is excluded)
WORKER_THREADS           = 16
WALK_MS                  = 1933.4
PARSE_MS                 = 3325.1
MERGE_MS                 = 923.7
TOTAL_MS                 = 6182.3
MB_PER_SECOND            = 20.3
PEAK_WORKING_SET_BYTES   = 1,219,928,064
WALK_TRUNCATED_FILES     = 0
UNREADABLE_FILES         = 0
```

Scaling, same code path, three points:

| Files | Total ms | Âµs/file |
|---|---|---|
| 47 | 520.7 | 9737.5 |
| 461 | 5729.4 | 10082.1 |
| 4607 | 24060.3 | 5050.5 |

Cost per file **halves** at full scale â€” the walk dominates at small sizes and
amortises. The absolute time at the largest point is inflated because three
indexes are built in one process against a 1.2 GB working set; the isolated
full build is the 4917 ms quoted above. Reported as measured.

Determinism is only claimed over a **declared** input set. This repository is
under active edit by other processes — one concurrent certification wrote ~30
files per run into `audit/RAWRXD_IDE_SANDBOX_MATRIX_001/` — so reproducibility
over a moving tree proves nothing either way. The gate therefore measures which
paths moved, then compares over an input set that excludes exactly those, and
always prints the excluded set:

```ini
DETERMINISM_ATTEMPTS             = 1
DETERMINISM_VOLATILE_PATHS_EXCLUDED = 4
DETERMINISM_BYTES_A              = 72698877
DETERMINISM_BYTES_B              = 72698877
DETERMINISM_HASH_A               = e671252de518e509
DETERMINISM_HASH_B               = e671252de518e509
```

Identical payloads over a fixed input set, with the excluded paths named rather
than dropped. In an earlier run against a quiescent tree the same check needed
no exclusions at all and matched on the first attempt. When the algorithm is
genuinely non-deterministic the check still fails — the retry loop reports
`payload differed`, and `DETERMINISM_VERDICT` says so rather than blaming the
input.

---

## 6a. A newly found blocker: RawrEngine cannot be built in a clean tree

I originally declined to touch `semantic_code_intelligence.cpp` on the grounds
that I could not rebuild its two shipping targets within an evidence budget.
**That was an excuse, and it was wrong.** The targets are genuinely
unbuildable, for a reason that has nothing to do with budget:

```text
CMakeLists.txt:3512  add_custom_target(regen-ssot-beacons
  COMMAND powershell -File ${CMAKE_SOURCE_DIR}/tools/sync_ssot_beacon_symbols.ps1
  COMMAND powershell -File ${CMAKE_SOURCE_DIR}/tools/generate_ssot_beacon_table.ps1
CMakeLists.txt:3520  add_custom_target(verify-ssot-ext-ownership
  COMMAND powershell -File ${CMAKE_SOURCE_DIR}/tools/verify_ssot_ext_ownership.ps1

CMakeLists.txt:3650  add_dependencies(RawrEngine regen-ssot-beacons verify-ssot-ext-ownership)
CMakeLists.txt:4013  add_dependencies(RawrXD_Gold regen-ssot-beacons)
```

All three scripts are absent from disk:

```ini
tools/sync_ssot_beacon_symbols.ps1     exists = 0
tools/generate_ssot_beacon_table.ps1   exists = 0
tools/verify_ssot_ext_ownership.ps1    exists = 0
```

`cmake --build build_scitgt --target RawrEngine` fails at step 16 of 273, before
compiling anything, and requesting a single object file fails at the same
prerequisite:

```text
FAILED: [code=4294770688] CMakeFiles/verify-ssot-ext-ownership
The argument 'F:/~dev/rawrxd/tools/verify_ssot_ext_ownership.ps1' to the -File
parameter does not exist.
```

So the fix in §5.1 is verified as far as the build graph permits and no
further:

```ini
SEMANTIC_TU_COMPILES_STANDALONE            = 1  (cl exit 0)
SEMANTIC_TU_LINKS_AND_RUNS                  = 1  (semantic_code_intelligence_cert, 11/11)
RAWRENGINE_CLEAN_TREE_BUILD                 = 0  (blocked above, pre-existing)
RAWRXD_GOLD_CLEAN_TREE_BUILD                = 0  (blocked above, pre-existing)
BLOCKER_PRESENT_BEFORE_THIS_WORK            = 1
```

This is a separate gate (`RAWRXD_SSOT_BEACON_PREREQ_001`) in a different
subsystem. Restoring the three scripts means writing the generator behaviour
they imply, which is not authority this gate holds. It is recorded, not fixed.
Note that a *configure* succeeds here and `RAWRXD_DROPPED_SOURCE_TOTAL=0`
reports clean, so a green configure says nothing about whether either target
can build.

---

## 7. Binding

```ini
TARGET rawrxd_repo_intel                 = CONFIGURED   (static library, 4 sources)
TARGET repo_intelligence_cert            = CONFIGURED   (real executable, EXCLUDE_FROM_ALL)
TARGET semantic_code_intelligence_cert   = CONFIGURED   (real executable, EXCLUDE_FROM_ALL)
CTEST repo_intelligence_cert             = REGISTERED
CTEST semantic_code_intelligence_cert    = REGISTERED
CMAKE_CONFIGURE                          = PASS, RAWRXD_DROPPED_SOURCE_TOTAL=0
```

The CLI is a production surface, not a test island. `RawrModesCli.cpp` gained a
`repo` subcommand beside `audit`, `gate` and `cert`, and the `rawr` target's
source list gained the four `repointel` sources. All five translation units
compile together cleanly.

```text
rawr repo scope                     print the universe and every exclusion
rawr repo index|search|context      query the whole repository
rawr repo symbol|callers|callees|reachable
rawr repo includes|dependents|impact
rawr repo refresh                   re-index only what changed
rawr repo absence <name>            scope-guarded presence/absence claim
rawr repo ... --scope <root>[,...]  narrow deliberately; claims get refused
```

---

## 8. Ledger

```ini
RAWRXD_REPOSITORY_INTELLIGENCE_001      = PASS (14/14 measured checks)
CAPABILITY_INCREMENTAL_INDEXING          = PASS
CAPABILITY_CHANGED_FILE_INVALIDATION     = PASS
CAPABILITY_PERSISTENT_INDEX              = PASS
CAPABILITY_DETERMINISTIC_REBUILD         = PASS
CAPABILITY_SYMBOL_REFERENCE_GRAPH        = PASS
CAPABILITY_CROSS_FILE_REASONING          = PASS
CAPABILITY_AST_AWARE_CHUNKING            = PASS (SCOPE_TREE_STRUCTURAL, not a full AST)
CAPABILITY_DEPENDENCY_TRAVERSAL          = PASS
CAPABILITY_CONTEXT_RANKING               = PASS
CAPABILITY_REPOSITORY_SCALE_SEARCH       = PASS
CAPABILITY_VERY_LARGE_REPOSITORY         = PASS

REPO_WIDE_DISCOVERY_IS_ARCHITECTURAL     = 1
ABSENCE_CLAIMS_REFUSED_WHEN_NARROWED     = 1
FALSE_ABSENCE_DEMONSTRATED               = 1 (3009 files, plus the win32app repro)

LSP_WORKSPACE_SCOPE_FIXED_IN_SOURCE      = 1
LSP_WORKSPACE_SCOPE_FIX_RUNTIME_EVIDENCE = 0 (TU blocked by a missing include)
RAWR_REPO_INTEL_BOUND_TO_SHIPPING_CLI    = 1

SEMANTIC_CODE_INTELLIGENCE_BOUND_TO_TARGETS      = 2
SEMANTIC_CODE_INTELLIGENCE_INDEXER_IMPLEMENTED  = 1
SEMANTIC_CODE_INTELLIGENCE_QUERY_SURFACE_LIVE   = 1
SEMANTIC_CODE_INTELLIGENCE_QUERIES_VERIFIED     = 11/11
SEMANTIC_CODE_INTELLIGENCE_REJECTS_MISSING_FILE = 1
SEMANTIC_FILES_INDEXED_DOUBLE_COUNT_BUG         = FIXED (12 -> 6)
RAWRENGINE_CLEAN_TREE_BUILD                     = BLOCKED_PRE_EXISTING_MISSING_SCRIPTS
RAWRXD_GOLD_CLEAN_TREE_BUILD                    = BLOCKED_PRE_EXISTING_MISSING_SCRIPTS
HARDCODE_MODEL_LOADED_TRUE_IN_DEAD_FILE          = 2
WIN32IDE_SEMANTIC_INDEX_CPP_DECLARED_BUT_ABSENT  = 1
RAW_RXD_IDE_FILEINDEX_IMPLEMENTATION_EXISTS      = 0
```

Gates that remain closed regardless of this work, per the corrected ledger:
`RAWRXD_RECEIPT_IMMUTABILITY_AUTHORITY_001` is retracted, and
`RAWRXD_SINGLE_WRITER_AUTHORITY_001` still fails recursively. Nothing here
advances either.

---

## 9. Reproduce

```powershell
cmake -S F:\~dev\rawrxd -B F:\~dev\rawrxd\build_repointel -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build F:\~dev\rawrxd\build_repointel --target repo_intelligence_cert semantic_code_intelligence_cert

F:\~dev\rawrxd\build_repointel\bin\repo_intelligence_cert.exe `
  --root F:\~dev\rawrxd `
  --out  F:\~dev\rawrxd\audit\RAWRXD_REPOSITORY_INTELLIGENCE_001\RECEIPT.txt `
  --cache F:\~dev\rawrxd\build_repointel\repo_intel_cache

F:\~dev\rawrxd\build_repointel\bin\semantic_code_intelligence_cert.exe F:\~dev\rawrxd `
  > F:\~dev\rawrxd\audit\RAWRXD_REPOSITORY_INTELLIGENCE_001\SEMANTIC_SURFACE.txt
```

Exit codes are derived, never assumed: `repo_intelligence_cert` returns `0`
when all 14 checks pass, `5` when any fails, `3` when an absence claim was
refused for scope; `semantic_code_intelligence_cert` returns `0` when all 11
query checks pass, `6` when any fails — which is what happens if the query
surface goes hollow again. The harness edits `src/repointel/ScopeTree.hpp`
during the incremental test and restores it byte-for-byte;
`INCR_VICTIM_RESTORED=1` records that it did.