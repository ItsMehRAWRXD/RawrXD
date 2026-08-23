# VAL-051.7 — Extra C: GGUF Integrity Boundary

## Document Identity
- **Extra:** C
- **Version:** 1.0
- **Date:** 2026-08-22

---

## Validation Requirements

| Check | Method |
|-------|--------|
| Tensor offset validation | `offset + size <= fileSize` |
| Tensor size validation | `size > 0` |
| Tensor type validation | Known GGML type enum |
| Dimension validation | Rank > 0, all dims > 0 |
| Quantization block-size | Matches type specification |
| Alignment validation | Warn if not 64-byte aligned |
| File-size boundary | Header + metadata + tensors <= fileSize |
| Metadata/index consistency | Tensor count matches index entries |
| Source-byte checksum | Optional SHA-256 per tensor |

## Negative Fixtures

- Invalid tensor offset (past EOF)
- Zero-length tensor
- Mismatched quantization type
- Corrupted header
- Truncated file
