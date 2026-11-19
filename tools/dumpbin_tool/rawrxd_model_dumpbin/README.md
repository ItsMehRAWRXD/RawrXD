# RawrXD Model DumpBin

A standalone, read-only GGUF v2/v3 structural inspector. It does not load tensor payloads into RAM, transform models, or claim to trace live inference.

## Build on Windows

Run `build_windows.bat` from an **x64 Native Tools Command Prompt for VS 2022**.

## Examples

```powershell
.\rawrxd_model_dumpbin.exe --source "F:\OllamaModels\blobs\sha256-8476acca2ca7dc4dd86ad2e069cb270fdbd44287d9ff3006d86e9a54cc19acd1" --metadata --max-items 30
.\rawrxd_model_dumpbin.exe --source "F:\OllamaModels\blobs\sha256-8476acca2ca7dc4dd86ad2e069cb270fdbd44287d9ff3006d86e9a54cc19acd1" --experts --reap-check
.\rawrxd_model_dumpbin.exe --source model.gguf --metadata --tensors --json > model_report.json
```

`--reap-check` only checks for matching stacked expert tensor **names**. It is not a compression authorization, expert geometry check, or proof of compatibility.

## Safety and scope

- Never writes to model files.
- Bounded reads for large tokenizer arrays (arrays are skipped without loading their contents).
- Reports metadata entry index and byte offset on parse failure.
- Does not infer tensor byte sizes from quantization types.
- Does not validate full multi-shard completeness; inspect each shard separately.
- Does not trace GPU, loading allocations, or token generation. Those require instrumentation in Deep2 and are intentionally reported as not observed.
- Do not use JSON reports containing sensitive model paths without reviewing them first.
