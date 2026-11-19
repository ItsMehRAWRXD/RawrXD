# S004 Q/K/V mapping revalidation

Revalidated against `evidence/same_sha_acceptance_20261119/ref/pos4`.

| Boundary | Selected artifact | Bytes | SHA-256 equals duplicate |
|---|---|---:|---|
| Q layer 0 | `q_L0__dup1.bin` | 6144 | `__dup2`: yes |
| K layer 0 | `k_L0__dup1.bin` | 1024 | `__dup2`: yes |
| V layer 0 | `v_L0__dup1.bin` | 1024 | `__dup2`: yes |

The retained operation mapping remains Q/K/V `__dup1`; `__dup2` is byte-identical
for these layer-0 artifacts. The base and `__dup3` variants remain distinct and
are not substituted. `attn_proj` remains without a corresponding reference
activation, so this revalidation does not close strict parity.

```ini
S004=PASS_MAPPING_REVALIDATED
QKV_VARIANT=__dup1
DUP2_BYTE_IDENTITY=PASS
ATTN_PROJ_REFERENCE=ABSENT
STRICT_PARITY=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
