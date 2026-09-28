RAWRXD_MODEL_CAPABILITY_SCRAPER_001

Purpose: passive standalone GGUF capability extraction. It does not instantiate Deep2,
Vulkan, shaders, schedulers, performance gates, or runtime fallback paths.

It reports model-file truth only: architecture, context, geometry, tokenizer/vocab,
GQA, RoPE, MoE/expert structure, SSM/recurrent structure, MLA metadata, chat template,
Q/K norm structure, tensor quantization histogram, and key model tensors.

It deliberately does NOT report whether RawrXD currently supports those capabilities.
That keeps model capability separate from code complexity and end-to-end limitations.

Build:
  build_probe.bat

Single model:
  model_capability_probe.exe "F:\models\model.gguf" > model.capability.txt

Fleet scrape:
  pwsh -NoProfile -File .\scan_model_fleet.ps1 -Probe .\model_capability_probe.exe -Root "G:\OllamaModels" -OutDir .\capability_manifests

Non-interference:
  read-only file access only; no environment changes; no GPU init; no Deep2 calls;
  no benchmark counters; no shader load; no model mutation.
