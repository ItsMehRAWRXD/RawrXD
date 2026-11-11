# Q4_0 Preprocessed Block ABI - FROZEN v1.0

## Status: PRODUCTION READY

This ABI is frozen and locked for Kernel Registry integration.

## Binary Layout

```
PreprocessedQ4Block (128 bytes, 64-byte aligned)
├── Q4BlockHeader header (16 bytes)
│   ├── uint32_t magic      = 0x51345030 ('Q4P0')
│   ├── uint32_t version    = 1
│   ├── uint32_t block_count
│   └── uint32_t original_elements
├── float scale             (4 bytes) at offset 16
├── int8_t weights[64]      (64 bytes) at offset 20
└── uint8_t padding[44]     (44 bytes) at offset 84
```

## Static Assertions (ABI Contract)

```cpp
static_assert(sizeof(PreprocessedQ4Block) == 128);
static_assert(alignof(PreprocessedQ4Block) == 64);
static_assert(offsetof(PreprocessedQ4Block, header) == 0);
static_assert(offsetof(PreprocessedQ4Block, scale) == 16);
static_assert(offsetof(PreprocessedQ4Block, weights) == 20);
static_assert(sizeof(Q4BlockHeader) == 16);
static_assert(offsetof(Q4BlockHeader, magic) == 0);
static_assert(offsetof(Q4BlockHeader, version) == 4);
```

## Assembly Offsets

The AVX-512 kernel uses these fixed offsets:
- Scale: `[rbx + 16]` (4 bytes, broadcast to zmm)
- Weights Pass 1 (0-15): `[rbx + 20]` (16 bytes)
- Weights Pass 2 (16-31): `[rbx + 36]` (16 bytes)
- Weights Pass 3 (32-47): `[rbx + 52]` (16 bytes)
- Weights Pass 4 (48-63): `[rbx + 68]` (16 bytes)

## Change Policy

**NO CHANGES ALLOWED** to this layout without:
1. Bumping Q4BlockHeader::VERSION to 2
2. Updating all assembly kernels
3. Re-running full validation suite
4. Updating Kernel Registry dispatch

## Validation Results

- ASM Kernel: PASS (zero error)
- Cache Alignment: PASS (64-byte aligned)
- Fused Pipeline: PASS (0.0105% tolerance failures, 17.61x speedup)

## Integration Date

2026-07-20 - Kernel Registry integration authorized.
