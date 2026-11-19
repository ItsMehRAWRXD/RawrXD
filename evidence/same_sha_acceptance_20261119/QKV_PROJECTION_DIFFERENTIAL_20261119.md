# Q/K/V projection differential

Using `first_divergence_pos0.json` and the established reshaped `__dup1`
reference variants:

- Q compared: `28/28` layers
- K compared: `28/28` layers
- V compared: `28/28` layers
- Lowest observed Q/K/V cosine: `0.999999999996037` (block 6 K)
- That boundary max absolute error: `9.5367431640625e-07`
- Q/K/V projection boundaries remain above the `0.9999` diagnostic threshold.

This rules out a material Q/K/V projection mismatch for the retained position-0
trace. It does not rule out position-dependent attention-state or downstream
softmax/AV differences, and does not close strict parity.

`S033=QKV_BOUNDARY_BOUNDED_PASS`
`STRICT_PARITY=OPEN`
`PROMOTE=0 CERTIFIED=0 RELEASE=HELD`
