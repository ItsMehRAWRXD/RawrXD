# Deep2 Qwen4Exp reverse-engineered operator contract

Tensors: 1224

| Operator | Tensor count | Contract geometry | Native executable |
|---|---:|---|---|
| QSA | 48 | indexer tensors, top-k compressed-key attention | NO |
| GDN | 252 | selective gated delta state; ssm_a=[48] | NO |
| PLE | 7 | causal conv=[4,10240] | NO |
| HYPERCONNECTION | 387 | down=[10240,320], inject=[10240,4], up=[320,10240] | NO |
| SPARSE_MOE | 144 | gate=[2560,640,512], 512 experts | NO |

Geometry checks: PASS
Certification: NOT_CERTIFIED (native Vulkan lowering and parity are still required)
