# Q4_K/Q6_K quantized dot parity

- Executable: `build/bin-msvc/Release/kquant_dot_parity.exe`
- Executable SHA-256: `8FC2D2E010A2E02FB2F6D7CD9AC55B77E29372AE9BC7729029DDC1350A7AD6F4`
- Q8_K packing: PASS, 32 blocks, zero mismatches
- Q4_K dot versus Q8_K: PASS, 8 blocks, worst absolute/relative error `0`
- Q6_K dot versus Q8_K: PASS, 8 blocks, worst absolute/relative error `5.36e-7`
- Tolerance: `1e-5`
- Process exit: `0`

`S038=QUANTIZED_DOT_PARITY_PASS`
`FULL_MODEL_PARITY=OPEN`
`PROMOTE=0 CERTIFIED=0 RELEASE=HELD`
