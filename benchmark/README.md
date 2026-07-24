# RawrXD Benchmark Package

## Quick Start

```bash
# 1. Clone and checkout verified commit
git clone https://github.com/ItsMehRAWRXD/RawrXD.git
cd RawrXD
git checkout $(cat benchmark/COMMIT_SHA)

# 2. One-command build
./benchmark/build.sh

# 3. Run validation suite
./benchmark/validate.sh

# 4. Generate report
./benchmark/report.sh
```

## Package Contents

| Component | Purpose | Status |
|-----------|---------|--------|
| `build.sh` | Reproducible build from clean checkout | ✅ Implemented |
| `validate.sh` | Tokenizer, tensor, layer correctness | ✅ Implemented |
| `benchmark.sh` | Performance vs llama.cpp | ✅ Implemented |
| `docker/` | Containerized environment | 📋 Planned |
| `models/` | Test model manifests | ✅ Implemented |
| `reports/` | Generated validation outputs | 📋 Auto-generated |
| `docs/` | Reproduction instructions | ✅ Implemented |

## Validation Matrix

| Test | Reference | Tolerance | Status |
|------|-----------|-----------|--------|
| Tokenizer Parity | HuggingFace | 100% match | ⏳ Pending |
| Tensor Loading | PyTorch | Bit-exact | ⏳ Pending |
| Layer Forward | llama.cpp | < 0.1% RMSE | ⏳ Pending |
| KV Cache | Reference impl | Bit-exact | ⏳ Pending |
| End-to-End | Known outputs | Perplexity match | ⏳ Pending |

## Performance Targets

| Metric | Target | Baseline (llama.cpp) | Status |
|--------|--------|---------------------|--------|
| Tokens/sec | ≥ 90% of baseline | 100% | ⏳ Pending |
| Memory overhead | ≤ 110% of baseline | 100% | ⏳ Pending |
| Startup latency | ≤ 5s | ~3s | ⏳ Pending |
| Context scaling | Linear to 128K | Reference | ⏳ Pending |

## CI Artifacts

Every commit produces:
- Build logs
- Validation reports
- Benchmark results
- Coverage metrics

View latest: [CI Dashboard](https://ci.rawrxd.dev)

## Contact

For reproduction issues: open a GitHub issue with `benchmark` label.
