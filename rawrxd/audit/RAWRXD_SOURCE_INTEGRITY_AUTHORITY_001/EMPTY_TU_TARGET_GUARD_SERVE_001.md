# RAWRXD_EMPTY_TU_TARGET_GUARD_001 — serve variant + instrument repair

Date: 2026-10-05
Type: containment repair, instrument repair, and two corrections to my own prior report

```ini
CONFIGURE_EXIT (default)              = 0    CMAKE_ERRORS = 0
CONFIGURE_EXIT (RAWRXD_BUILD_CLI=ON)  = 0    CMAKE_ERRORS = 0
RAWRXD_SERVE_TARGET                   = WITHHELD
rawrxd-serve refs in build.ninja      = 0
```

---

## 1. CORRECTION — the "37 targets" figure I reported was wrong

```ini
                        BEFORE (buggy)   AFTER (repaired)
  target declarations parsed       403                   390
  targets naming any hollow         39                    26
  targets naming leak               37                    24
```

Cause: two defects in `cmake/source_integrity_authority.cmake`.

```ini
DEFECT_A  the record carried ${_hollow_inline} while the count beside it was
          ${_n_leak}, so a LEAK count was annotated with ANY-HOLLOW paths
DEFECT_B  a CMake list joins with ";", and the TSV writer replaces ";" with
          newline to emit one row per target -- so every target with more than
          one source was split across lines. targets_naming_leak.tsv read as 37
          rows with ragged, truncated columns for exactly this reason.
```

Cross-checking one record against its own counts exposed it: `rawrxd-serve`
reported `LEAK=6` beside a single path. **True figure: 24 targets, not 37.**
The fix records both lists, joined with `|` (which cannot occur in a path).

## 2. CORRECTION — `rawrxd-serve` is not a serving surface

```ini
src/serve/rawrxd_serve_main.cpp   25 bytes, verbatim:  int main(){ return 0; }
6 further src/serve sources        459 bytes each, comment-only
rawrxd-serve target                EXCLUDE_FROM_ALL + EXCLUDE_FROM_DEFAULT_BUILD
build.ninja references             0   (before and after this change)
```

The target was never built and never contained a server. **The shipped server is
`rawr-server`** (OpenAI-compatible, port 11435), which is a different target and
is present in the build.

So the premise that this was "the first bleeding artery because it is a real
serving surface" was wrong on both counts: it was not real, and the count it came
from was inflated. The contamination concern for downstream server receipts does
not apply — there is no server-green receipt to contaminate.

## 3. NEW DEFECT FAMILY — restoration re-armed a suppression guard

The block's own comment states its intent:

```text
RAWRXD_SERVE_NOT_BUILT_001
  "The target is therefore declared only when its primary implementation
   exists, and its absence is reported at STATUS level."
```

The guard was `if(EXISTS src/serve/rawrxd_serve.cpp)`. That intent was defeated by
the graph-restoration machinery: the six `src/serve` sources were materialised as
459-byte comment-only units, so `EXISTS` became true and the guard that existed
**specifically to suppress this target began admitting it.**

```text
A guard written against EXISTENCE cannot distinguish a restored stub
from a restored implementation. Restoration therefore silently switched on
the thing restoration was meant to keep switched off.
```

This is `RAWRXD_EMPTY_TU_TARGET_GUARD_001` running in the **opposite direction**
from the DAP adapter:

```text
DAP    EXISTS let a hollow unit INTO a target
SERVE  EXISTS let a hollow unit DISABLE A SUPPRESSION
```

Both are one root cause: existence used as a proxy for implementation.

### Repair

The guard now applies the census predicate (`RAWRXD_GRAPH_RESTORED_001`), the same
one the DAP fix uses, and restores the intent its own comment already described.

```text
[SERVE] RAWRXD_SERVE_TARGET=WITHHELD
[SERVE] RAWRXD_SERVE_REASON=primary implementation is a graph-restoration stub
[SERVE] RAWRXD_SERVE_SURFACE=NONE  (the shipped server is target rawr-server, port 11435)
[SERVE] TO_IMPLEMENT=write a real server, or remove this declaration
```

Verified under `RAWRXD_BUILD_CLI=ON`, the configuration that actually reaches this
block (it is skipped entirely by default). Configure exit 0, and `rawrxd-serve`
contributes 0 references to the generated build graph.

## 4. KNOWN INSTRUMENT LIMITATION — the leak count did not improve, and cannot

```ini
RAWRXD_TARGETS_NAMING_LEAK_INLINE = 24   (unchanged by the two guards)
```

`RAWRXD_SOURCE_INTEGRITY_AUTHORITY_001` audits the CMake **text**. A runtime guard
that withholds a target does not remove its declaration from the text, so both the
DAP and SERVE fixes prevent a false green at configure time while the census keeps
counting the declaration.

That is honest reporting, not a failed fix — but it means the count is an upper
bound on defect sites, not a count of live false greens. Making it exact requires
a guard-aware census that understands withholding predicates, which is not built.
Recorded as an open item rather than papered over.

`RawrXDScriptDAPAdapter` and `rawrxd-serve` both remain listed for this reason.

## 5. State

```ini
SOURCE_PATH_COMPLETENESS              = PASS   1304/1304
SOURCE_IMPLEMENTATION_CENSUS          = OPEN   301 HOLLOW (23%)
EMPTY_REGISTRY_INTEGRITY               = PASS   union-preserving, shrink-detecting
DAP_TARGET_INTEGRITY                   = PASS   guard proven in both directions
SERVE_TARGET_INTEGRITY                 = PASS   guard proven, CLI=ON
TARGET_SOURCE_FILTER_AUTHORITY         = OPEN   24 declarations (was reported 37)
GUARD_AWARE_CENSUS                     = OPEN   not built; leak count is an UPPER BOUND
RAWXD_SERVE                            = WITHHELD  fossil; real surface is rawr-server

COMPLETION_CRITERION
  Every declared build surface is exactly one of
  IMPLEMENTED | WITHHELD | INTENTIONALLY_EMPTY | RETIRED,  with UNKNOWN = 0
```