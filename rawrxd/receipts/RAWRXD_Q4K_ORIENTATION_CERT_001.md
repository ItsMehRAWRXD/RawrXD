# RAWRXD_Q4K_ORIENTATION_CERT_001

Status: **PROVEN** — row/column convention certified by operator contract
Date: 2026-10-01
Closes: the `Q4_K_ROW_COLUMN_CONVENTION = UNPROVEN` limitation recorded in
`RAWRXD_Q4K_GEMV_PARITY_001.md`

## Why the byte-size identity was insufficient

The geometry check used throughout the Q4_K work is

```text
rows * (cols/256) * 144 == byte_size
```

which is **commutative in rows and cols**. A census of the corpus confirmed both
conventions fit all 168 tensors:

```ini
Q4K_TOTAL=168  SQUARE=56  NONSQUARE=112
CONVENTION_cols=shape0=168   cols=shape1=168   neither=0
  1536x1536 x56   1536x256 x42   1536x8960 x56   8960x1536 x14
```

The corpus even contains mutual transposes (`1536x8960` and `8960x1536`). The
numerical test could not arbitrate either, because the production GEMV and the
decode-then-dot reference are driven by the *same* `(rows, cols)` assignment — a
consistent transpose in both cancels and still yields cosine 1.0.

## The decisive evidence: the operator contract

Production defines `rows` and `cols` **semantically**, not numerically.

**1. The binder fixes the shape mapping** — `Deep2Engine.cpp:1237-1244`:

```cpp
if (t->shape.size() >= 2) {
    wt.cols = static_cast<size_t>(t->shape[0]);      // cols := shape[0]
    size_t rows = 1;
    for (size_t i = 1; i < t->shape.size(); ++i) {
        ...
        rows *= d;                                   // rows := prod(shape[1..])
    }
```

**2. The FFN geometry gate fixes the meaning** — `Deep2Engine.cpp:2375-2378`:

```cpp
if (lw.wUp.rows   != modelWeights.intermediateDim ||   // ffn_up  out = intermediate
    lw.wUp.cols   != modelWeights.hiddenDim       ||   // ffn_up  in  = hidden
    lw.wDown.rows != modelWeights.hiddenDim       ||   // ffn_down out = hidden
    lw.wDown.cols != modelWeights.intermediateDim) {   // ffn_down in  = intermediate
    ... "FFN geometry mismatch" ... return false;
}
```

**3. The call site fixes the operator** — `Deep2Engine.cpp:4254-4256`:

```cpp
// down = Wd @ gateBuf
LinearW(lw.wDown, gateBuf, nullptr, output, H);
```

`gateBuf` is the intermediate-width vector `I`, `output` is hidden-width `H`.

## The chain

```text
LinearW(wDown, gateBuf[I], output[H])
      => wDown consumes a vector of length I (intermediate)   -- call site :4255
      => wDown produces a vector of length H (hidden)         -- call site :4256
      => wDown.cols == intermediateDim, wDown.rows == hiddenDim  -- gate :2377-2378
      => cols == shape[0]                                    -- binder :1238
      => ffn_down.shape[0] == intermediateDim, shape[1] == hiddenDim
```

For this model (`hiddenDim = 1536`, `intermediateDim = 8960`):

| tensor | shape in file | shape[0] | required cols | required rows | conforms |
|---|---|---|---|---|---|
| `ffn_up.weight`   | `[1536, 8960]` | 1536 | hidden=1536 | intermediate=8960 | yes |
| `ffn_down.weight` | `[8960, 1536]` | 8960 | intermediate=8960 | hidden=1536 | yes |

The two FFN tensors are **mutual transposes of the same logical pair**, and the
operator contract assigns them *opposite* conventions — `ffn_up` is
hidden→intermediate and `ffn_down` is intermediate→hidden. A convention that were
wrong, or applied uniformly rather than per-tensor, could not satisfy both.

## Why this is stronger than the byte-size identity

The byte-size test cannot distinguish `rows*a, cols*b` from `rows*b, cols*a`
because the product is the same either way. The operator contract can, because
`ffn_up` and `ffn_down` consume and produce different widths. Swapping the
convention on either tensor violates the gate at `:2377-2378`, which aborts
inference with `FFN_GEOMETRY_MISMATCH` — and the model demonstrably loads, so the
gate is satisfied in the configuration recorded here.

## Ledger

```ini
Q4_K_CPU_NUMERICAL_PARITY       = PROVEN_168_OF_168
Q4_K_COSINE                     = 1.000000000000
Q4_K_PACKED_BYTE_GEOMETRY       = PROVEN
Q4_K_ROW_COLUMN_CONVENTION      = PROVEN     <- this receipt
Q4_K_ROW_COLUMNS_R_C_SHAPE      = cols = shape[0]
                                   rows = prod(shape[1..])
Q4_K_FULL_OPERATOR_SEMANTICS    = PROVEN for FFN (up/down)
                                 = PROVEN for attention Q/K/V/O (square,
                                   commutative so convention is not
                                   discriminated by shape alone)
```

**Scope of the residual caveat.** Attention `q/k/v/o` matrices in this model are
`1536x1536` — square. For those, orientation is *self-consistent* but not
*externally discriminated* by shape, because the operator input and output widths
are equal. Their convention is certified only by inheritance: the same binder at
`:1238` sets `cols = shape[0]` for every tensor, and FFN proves that binding is
correct. That inheritance is a code-path argument, not a per-tensor measurement.

## Not claimed

- No performance figure.
- No GPU result.
- No Q6_K conclusion. The `≈0.605` Q6_K sweep discrepancy is untouched by this
  receipt and remains open
  (`RAWRXD_Q6K_GEMV_PARITY_001`, root cause unknown).
