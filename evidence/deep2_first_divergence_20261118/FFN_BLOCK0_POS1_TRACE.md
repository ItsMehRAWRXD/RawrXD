# Block-0 FFN trace after interleaved GDN fix

Model: qwen3.8-27B, tokens `1 185`, position 1, block 0.

| Boundary | Cosine | Max abs | RMS |
|---|---:|---:|---:|
| Gate projection | 0.99999996765 | 5.4348e-4 | 1.2035e-4 |
| Up projection | 0.99999996021 | 4.2325e-4 | 1.1710e-4 |
| SwiGLU | 0.99999994216 | 5.8138e-4 | 4.7771e-5 |
| Down projection / `ffn_out` | 0.99999937060 | 2.7639e-3 | 6.7887e-4 |
| Residual2 | 0.99999882039 | 2.7634e-3 | 6.7887e-4 |

The first available comparable FFN boundary is the gate projection. Its small
quantized difference precedes the larger down-projection error; the trace does
not establish a defective down-projection kernel. The FFN norm reference tensor
was not retained, so no source correction is justified from this trace alone.

```ini
POS1_BLOCK0_FFN_ROOT_CAUSE=NOT_ESTABLISHED
FULL_LOGIT_PARITY=FAIL
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
