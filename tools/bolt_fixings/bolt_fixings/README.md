# RawrXD Bolt fixings — no third-party source dependencies

This package **does not** claim to implement Bolt Mamba-2, LatentMoE, NVFP4 or IQ2_XXS inference. Those require exact tensor formats and reference parity. It supplies useful fail-closed foundation instead:

- `gguf_inventory.cpp`: native GGUF v2/v3 metadata/tensor header inventory; prints quantization type IDs and names, architecture, shape, offsets. Does not read weights, allocate tensors, or execute inference. Rejects unsupported metadata encodings.
- `bolt_admission.hpp`: previous operator-certification admission gate.
- `bolt_admission_test.cpp`: admission unit tests.
- `cert_integrity.py`: read-only production certification contradiction detector. Only three known receipt mappings are configured; unknown gates fail closed.

## Windows build

```
cd /d F:\rawrxd\tools\bolt_fixings
cl /nologo /std:c++20 /EHsc /W4 gguf_inventory.cpp /Fe:gguf_inventory.exe
cl /nologo /std:c++20 /EHsc /W4 bolt_admission_test.cpp /Fe:bolt_admission_test.exe
bolt_admission_test.exe
gguf_inventory.exe "F:\path\to\bolt.gguf" > bolt_inventory.txt
py -3 cert_integrity.py F:\rawrxd
```

`gguf_inventory` requires a single GGUF file; split/sharded models require each shard inspected separately. GGML quantization IDs are printed as raw numeric IDs deliberately, to avoid guessing newer NVFP4 type mappings. The parser does not certify tensor data offsets, checksums, model completeness, or inference support.

No source/models/Git data are deleted or modified by these programs.
