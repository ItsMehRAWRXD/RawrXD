# S029 — GGUF metadata and tensor geometry

Date: 2026-11-19  
Source SHA: `fe93de06e8a67cceefa9ff74848d1ea1b0f5d8db`

## Source findings

Deep2 loads authoritative GGUF metadata and tensor dimensions, then reconciles
model configuration against actual tensor geometry. The loader validates
nonzero hidden/layer/head dimensions, derives Q/K/V geometry for GQA, infers
head dimension from projection tensors when metadata is inconsistent, derives
vocabulary size from the embedding tensor, and rejects invalid dimensions
before allocation.

Quantized tensor records preserve GGUF type, dimensions, byte offsets, and
row/column interpretation. The existing Batch21 registry test also loads a
real GGUF tensor and validates its matrix geometry before dispatch.

## Acceptance status

The geometry validation boundary is source-verified, but a complete matrix of
all supported GGUF types/shapes was not executed in this sprint. Unsupported
or incomplete architectures remain fail-closed at their specific graph
construction boundaries.

```ini
GGUF_METADATA_VALIDATION=SOURCE_VERIFIED
QKV_GQA_GEOMETRY=SOURCE_VERIFIED
QUANTIZED_TYPE_MAPPING=SOURCE_VERIFIED
ALL_SUPPORTED_SHAPES_RUNTIME=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
