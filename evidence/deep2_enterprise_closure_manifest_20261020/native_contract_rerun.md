# Deep2 Qwen4Exp reverse-engineered operator contract

Tensors: 1224

| Operator | Total tensors | Primary block tensors | Auxiliary/global tensors | Contract geometry | Native executable |
|---|---:|---:|---:|---|---|
| QSA | 48 | 48 | 0 | indexer tensors, top-k compressed-key attention | NO |
| GDN | 252 | 216 | 36 | selective gated delta state; ssm_a=[48] | NO |
| PLE | 7 | 6 | 1 | causal conv=[4,10240] | NO |
| HYPERCONNECTION | 387 | 384 | 3 | down=[10240,320], inject=[10240,4], up=[320,10240] | NO |
| SPARSE_MOE | 144 | 144 | 0 | gate=[2560,640,512], 512 experts | NO |

Ownership reconciliation: GDN 216+36, PLE 6+1, HYPERCONNECTION 384+3; tensor names remain unique across both shards.

Geometry checks: PASS
Certification: NOT_CERTIFIED (native Vulkan lowering and parity are still required)
