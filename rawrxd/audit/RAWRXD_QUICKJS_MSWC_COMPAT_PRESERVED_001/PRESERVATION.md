# RAWRXD_QUICKJS_MSWC_COMPAT_PRESERVED_001

Preservation record for uncommitted MSVC compatibility modifications inside the
`rawrxd/3rdparty/quickjs` submodule working tree.

**Nothing in the submodule was committed, reset, or updated.** This directory
is a byte-level snapshot so the changes survive any future submodule reset,
`git submodule update`, or clean. The parent branch does not reference these
files.

## Pinned state

```
submodule  rawrxd/3rdparty/quickjs
origin     https://github.com/bellard/quickjs.git   (upstream Bellard)
HEAD       04be246001599f5995fa2f2d8c91a0f198d3f34c
subject    run-test262: when updating errors, sort them so that it gives the
           same result with several threads
```

The submodule pointer in the parent tree is unchanged. Only the submodule's own
working tree is dirty.

## Snapshot contents

| File | Bytes | What it is |
|---|---|---|
| `quickjs_msvc_compat.patch` | 11567 | `git diff` against 04be2460, applies with `git apply`. **UTF-8, no BOM.** |
| `compat_msvc.h` | 1943 | untracked; the compatibility header itself |
| `quickjs_orig.c` | 0 | untracked; **empty file**, contents unexplained |
| `version.txt` | 12 | untracked; replaces the deleted `VERSION` |
| `git_status.txt` | 236 | `git status --porcelain` at snapshot time |
| `pinned_commit.txt` | 86 | the SHA above |

## Working-tree state at snapshot

```
 D VERSION
 M cutils.h
 M dtoa.c
 M quickjs.c
 M quickjs.h
?? compat_msvc.h
?? quickjs_orig.c
?? version.txt
```

Diffstat: 5 files, 56 insertions, 34 deletions.

## What the changes are

GCC/Clang builtins and attributes do not exist under MSVC. The patch introduces
a shim header and rewrites the call sites that used them.

`compat_msvc.h` is included at the top of `cutils.h` and `quickjs.h` and
provides:

- `#define __attribute__(...)` — drops all attribute expansions
- `__builtin_expect(x, y)` — folded to `(x)`
- `__builtin_clz` / `__builtin_clzll` / `__builtin_ctz` / `__builtin_ctzll` —
  implemented over `_BitScanReverse` / `_BitScanForward`, with the `_WIN64`
  64-bit intrinsic and a two-step 32-bit fallback for 32-bit targets
- `__builtin_frame_address(0)` — `_AddressOfReturnAddress()`
- `#define __maybe_unused`
- `PACKED_STRUCT_BEGIN` / `PACKED_STRUCT_END` — `__pragma(pack(push, 1))` and
  `__pragma(pack(pop))` under MSVC, empty under GCC. The non-MSVC branch also
  defines `PACKED_ATTR` as `__attribute__((packed))`.

Call-site rewrites:

- `cutils.h` — the three `packed_u64` / `packed_u32` / `packed_u16` structs move
  from `struct __attribute__((packed)) packed_u64 {...}` to
  `PACKED_STRUCT_BEGIN` / `struct packed_u64 {...}` / `PACKED_STRUCT_END`.
  Since `__attribute__` is defined away, the old form would otherwise have
  silently lost its packing guarantee rather than failing to compile.
- `quickjs.h` — `JS_DupValue` and `JS_DupValueRT` change
  `return (JSValue)v;` to `return v;`. The cast was a no-op on GCC; under MSVC
  it is rejected.
- `dtoa.c` — drops `#include <sys/time.h>`, which MSVC does not ship.
- `VERSION` deleted, replaced by `version.txt`.

## Two loose ends, recorded rather than resolved

- `quickjs_orig.c` is **0 bytes** and unreferenced by the build. Whether it is a
  placeholder or a leftover is not established. It was copied because it is
  untracked and would be lost on reset; it carries no content to lose.
- These are vendor-tree edits to a third-party project. They are currently
  reproducible only from a dirty checkout. If RawrXD genuinely requires them,
  the durable form is a controlled patch series or fork pinned to a known
  upstream commit -- not an incidental modified Bellard checkout.

## Restoration

The patch was first written with a PowerShell `>` redirect, which emits
**UTF-16LE** — `git apply` rejected it with `error: No valid patches in input`
and the file would have failed to restore at the moment it was needed. It was
rewritten as UTF-8 without BOM and re-verified. On any re-export, do the same:

```powershell
git -C F:\~dev\rawrxd\3rdparty\quickjs diff |
  Out-File -FilePath <dest> -Encoding utf8NoBOM
```

Then restore:

```powershell
cd F:\~dev\rawrxd\3rdparty\quickjs
git apply F:\~dev\rawrxd\audit\RAWRXD_QUICKJS_MSWC_COMPAT_PRESERVED_001\quickjs_msvc_compat.patch
Copy-Item F:\~dev\rawrxd\audit\RAWRXD_QUICKJS_MSWC_COMPAT_PRESERVED_001\compat_msvc.h .
Copy-Item F:\~dev\rawrxd\audit\RAWRXD_QUICKJS_MSWC_COMPAT_PRESERVED_001\version.txt .
```

Verify with `git status --porcelain` against `git_status.txt`.

### Snapshot integrity at time of writing

```
SHA256(quickjs_msvc_compat.patch)
  = 922BAF42BE28E7A9653B339ADABFEA0A08E4067023AC6E26BAF8F943A258B97C
git apply --check --reverse  <patch>  -> exit 0   (patch matches the dirty tree)
git apply --check           <patch>  -> exit 1   (already applied, as expected)
first 8 bytes = 64 69 66 66 20 2D 2D 67  ("diff --gi", i.e. plain UTF-8)
```

Both checks agreeing is what makes the snapshot trustworthy: the patch reverses
cleanly against the current tree, and fails forward-apply precisely because the
changes are already present.

## Scope

Preservation only. No claim is made here that the patched QuickJS builds, that
the compatibility layer is complete, or that RawrXD requires it.