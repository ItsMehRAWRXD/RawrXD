# ROM manifest binding suite — 2026-10-20

Status: **PASS (ROM geometry and descriptor binding)**

Executable: `F:\rawrxd\.build_rom_manifest_20261020\deep2_rom_manifest.exe`

Executable SHA-256: `2131FA5A2DD9A18D8750E60EF46A48291AA3541C372D6EB06595D7056D3B1067`

The executable was compiled from `tools/deep2_rom_manifest.cpp` and
`src/gguf/RawrXDGgufReader.cpp` with the local VS2022 BuildTools toolchain. It
uses the canonical `QuantTypeTable` for every dtype and byte-geometry check.

| Blob | Architecture | Tensors | Bound | Unknown / inconsistent | Verdict |
| --- | --- | ---: | ---: | ---: | --- |
| `models/nemotron-3.5-lightning-30b-Q4_K_M.gguf` | `nemotron_h_moe` | 417 | 417 | 0 / 0 | `BOUND_ALL` |
| Ollama `deepseek-r1:32b` blob | `qwen2` | 771 | 771 | 0 / 0 | `BOUND_ALL` |
| Ollama `gpt-oss:120b` blob | `gptoss` | 687 | 687 | 0 / 0 | `BOUND_ALL` |

The GPT-OSS run scanned and bound the complete 65,369,799,840-byte file without
materialising its weights. This establishes ROM-level availability and exact
descriptor geometry for the 120B model. It does not certify a forward pass,
finite logits, GPU residency, or throughput; those remain blocked on the
runtime's host-memory materialisation and gptoss graph/kernel path.

Per-model logs and exit codes are retained in the sibling directories:

- `rom_manifest_nemotron30b_q4_20261020T1440/`
- `rom_manifest_deepseek_r1_32b_20261020T1440/`
- `rom_manifest_gpt_oss_120b_20261020T1440/`
