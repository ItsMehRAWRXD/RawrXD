# Q8_K Quantized-Dot Parity — Layer/Position Decomposition

Model: llama3.2:3b (Q4_K), tokens [1, 185], positions 0 and 1, all 28 layers.
Tool: `tools/q8_boundary_audit.cpp` (self-contained reproduction of ggml's
`quantize_row_q8_K_ref` + `ggml_vec_dot_q4_K_q8_K_generic`).

## Decomposition

For every layer and position, the SAME engine input is packed with ggml's own
quantizer and dotted against the same Q4_K weight rows with ggml's own dot:

| Column | Meaning |
|--------|---------|
| A | rel(Deep2 output, ggml arithmetic on Deep2's input) |
| B | rel(llama.cpp output, ggml arithmetic on llama.cpp's input) |
| C | rel(Deep2 output, llama.cpp output) — the observed engine difference |
| I | rel(Deep2 input, llama.cpp input) — upstream drift |
| F | count of q8 bytes differing between the two packings (boundary flips) |

## Results (summary)

- **A is 5e-6 .. 1e-3 on EVERY layer and position** — the same magnitude as B.
  Deep2's k-quant dot reproduces ggml's own arithmetic on identical inputs
  everywhere. There is no dot-kernel defect.
- **C tracks I × F**: where F = 0 (layers 0–5, position 0) C is 2e-7..3e-7.
  Where the residual drift has grown and boundary flips reach 1000–2200
  (deeper layers, position 1), C reaches 1e-2 .. 2.4e-1.
- Position 1 layers 0–3 already show F = 27..1157 and I up to 5e-2 from
  accumulated residual drift.

## Conclusion

The remaining llama3.2:3b forward divergence is NOT a quantization-kernel
error. It is (i) sub-1e-5 arithmetic-order differences in fp32 operations
(norms, softmax, accumulates) accumulated through the residual stream, which
(ii) the Q8_K activation quantization amplifies at rounding boundaries: two
inputs differing at 1e-6 can pack to different q8 bytes, and a single flipped
byte moves the dot output by ~1e-3 relative on that row.

Tolerance consequence (per audit item 89): k-quant projections must be
certified against a reference with the input drift accounted for — a per-op
cos/rel gate alone cannot separate a kernel defect from drift amplification,
which is why this decomposition (same input through both arithmetics) is part
of the permanent certification.

Full table: `q8_boundary_audit <gguf> <run_dir> 28` (this directory's dumps
regenerate it; also captured in the run's boundary_audit.tsv).
