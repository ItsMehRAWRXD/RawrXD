# Deep2 local-model capability report

Source: `F:\\rawrxd-native-agent-001\\evidence\\E2E_DEEP2_REAP_LADDER_001\\deep2\\MATRIX.csv`

Scope: local Ollama models with reported size <= 30 GB (MB values converted using 1024 MB = 1 GB). A PASS requires exit 0, finite logits, and `gpu_complete=yes` in the recorded bench result.

## Runs that passed

| Model | Size | Decode TPS | Evidence |
|---|---:|---:|---|
| n4-tiny-oracle:latest | 637 MB | 3.835 | finite, GPU complete |
| qwen2.5-coder:1.5b-base | 986 MB | 1.269 | finite, GPU complete |
| embeddinggemma-2:740m | 1.3 GB | 16.999 | finite, GPU complete |
| llama3.2:3b | 2.0 GB | 1.296 | finite, GPU complete |
| qwen35-40b-heretic-q8:latest | 2.2 GB | 3.244 | finite, GPU complete |
| nemotron-3-nano:4b | 2.8 GB | 1.240 | finite, GPU complete |
| granite3.3:8b | 4.9 GB | 0.411 | finite, GPU complete |
| llama3.1:8b | 4.9 GB | 0.520 | finite, GPU complete |
| deepseek-coder-v2:16b | 8.9 GB | 0.660 | finite, GPU complete |
| starcoder2:15b | 9.1 GB | 1.129 | finite, GPU complete |
| deepseek-r1:32b | 19 GB | 0.167 | finite, GPU complete |
| bigdaddygnative:latest | 25 GB | 0.084 | finite, GPU complete |

## Under 30 GB but not passing

| Model | Size | Result | Recorded reason |
|---|---:|---|---|
| gemma3:4b | 3.3 GB | FAIL | missing `blk.0.attn_q.bias` |
| qwen3:8b | 5.2 GB | FAIL (exit 2) | bench verdict failed despite finite/GPU-complete markers |
| kiminoto/T0.0.1:latest | 6.6 GB | FAIL | `residualadd attn_proj` missing |
| pdurugyan/qwen3.5-9b-deepseek-v4-flash-Q4_K_M-v_2:latest | 6.6 GB | FAIL | GDN dimensions non-zero requirement failed |
| gpt-oss:20b | 13 GB | FAIL | `residualadd attn_proj` missing |
| qwen3.8:27b | 17 GB | FAIL | GDN dimensions non-zero requirement failed |
| flint:latest | 22 GB | FAIL | router zero weight |
| ornith-1.5:35b | 22 GB | FAIL | GDN dimensions non-zero requirement failed |
| nemotron-3.5-bolt:latest | 24 GB | FAIL | SSM weight GPU dispatch fell back to CPU |
| nemotron-3.5-lightning:30b | 25 GB | FAIL | ingest exited without diagnostic output |

## Result

`12/22` models at or below 30 GB passed the recorded Deep2 ladder. This is a capability snapshot for the frozen executable and test receipts, not a universal support claim. Kimi, DeepSeek, and MiniMax shard results are tracked separately in the shard-lane evidence; they are not included in this <=30 GB dense/local count.
