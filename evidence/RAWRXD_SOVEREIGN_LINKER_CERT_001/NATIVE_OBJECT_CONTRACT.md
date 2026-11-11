# Native Deep2/REAP Object Linkability Contract

Status: **DRAFT / INVENTORY IN PROGRESS** — not a PASS.  
Entry stub: **CLOSED**. `PROMOTE=0`. `WINDOWS_RUNTIME_CERT=0`.

## Scope separation

| Layer | Certifies | Status |
|-------|-----------|--------|
| Freestanding corpus | Exit-code PE via `rawrxd_link` + ExitProcess stub | 19/19 fresh @ `08f4f4f2…` |
| Deep2/REAP proxy | Multi-obj / data / BSS shapes under freestanding ABI | PROXY_PASS |
| Native Deep2/REAP objs | Real compiler outputs from Deep2/REAP TUs | **INVENTORY_PENDING → classify** |

Proxy PASS does **not** satisfy native compatibility.

## Classification (required)

Each inventoried `.obj` is one of:

| Class | Meaning |
|-------|---------|
| `FREESTANDING_LINKABLE` | No CRT/C++/TLS/helper imports beyond what `rawrxd_link` resolves today |
| `RUNTIME_DEPENDENT` | Needs CRT, C++ EH/RTTI, TLS, compiler helpers, or Windows APIs beyond ExitProcess stub |
| `UNSUPPORTED` | Wrong machine, corrupt COFF, or features the linker must reject |

## Fail-closed law

```
UNSUPPORTED | RUNTIME_DEPENDENT  (when linked by rawrxd_link without required runtime)
  => diagnostic on stderr
  => nonzero process exit
  => MUST NOT silently discard sections, symbols, relocations, or imports
```

Existing fail-closed behaviors already required for native path:

- Unresolved relocation / undefined symbol → link fail (`main.c`)
- Duplicate strong external → merge fail (`section_merge.c`)
- Malformed COFF header → reader reject (`coff_reader.c`)

## Inventory artifact

- Generator: `inventory_native_objs.ps1`
- Output: `native_object_inventory.json`
- Fields per object: path, sha256, machine, sections, undefined sample, classification, reasons, rejection predicate

## Isolated provenance

- Method: copy linker sources + corpus into `p2_isolated/` (does **not** clean main dirty tree)
- Script: `p2_isolated_rebuild.ps1`
- Output: `p2_isolated/isolated_provenance.json`
- If isolated linker SHA ≠ corpus-executed `08f4f4f2…`, record whether cause is build flags (`/LTCG` vs no-LTCG), path embedding, or source drift — do not claim bit-identical reproducibility until explained.

## Non-goals

- Reopening the entry stub unless a native failing test implicates it
- Inferring Windows runtime or five-OS certification from freestanding evidence
