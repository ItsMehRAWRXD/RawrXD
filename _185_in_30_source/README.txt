RAWRXD_DEEP2_185_IN_30_001

Authority target:
  185 tokens <= 30.000 seconds
  Required throughput: 6.166667 TPS

Native gate:
  deep2_185in30_gate.cpp
  - no third-party dependencies added
  - explicit 16-token warmup outside measured window
  - unified generateStream path
  - strict GPU
  - zero fallback
  - real GPU witness
  - fail closed when 30 s is exceeded before token 185

Immediate existing-gate runner:
  pwsh -NoProfile -File .\run_185in30_existing_gate.ps1 `
    -Bench F:\~dev\build_p2\qwen32_40tps_gate.exe `
    -Model G:\OllamaModels\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf

PASS is never inferred from ENGINE TPS alone.
