# Native non-repetitive weight compression evidence

`tensor_codec_benchmark` measures the actual native adaptive codec against a **raw tensor byte payload** extracted from a model. The input is **not** an entire GGUF file: its metadata, alignment and unrelated tensor headers would distort the result. The tool does not alter the source file.

Build the `tensor_codec_benchmark` CMake target, then run:

```text
tensor_codec_benchmark.exe path/to/extracted-f32-weight.bin
tensor_codec_benchmark.exe path/to/extracted-f32-weight.bin 0.001
tensor_codec_benchmark.exe path/to/extracted-q4-blocks.bin
```

The second invocation enables lossy F32->F16/BF16 candidates with a **maximum absolute error** of 0.001 per element. Do not use it on quantized blocks, FP16 or BF16 byte streams: the optional lossy mode assumes F32 values. For lossless runs, all decoded bytes must match the original exactly. The tool defaults to a 256 MiB input limit; an optional third argument sets the maximum MiB.

The codec compares raw, byte-run RLE, ordinary LZ4 and shuffled 32-bit-lane LZ4. Byte shuffling helps when non-identical 32-bit values have correlated exponent or mantissa bytes; it is not a way to compress incompressible random data. The benchmark reports encoded payload size, ratio, encode/decode time and maximum F32 absolute error. It does not include runtime index metadata, model quality, GPU residency or token throughput.

**Release gates still required:** actual GGUF tensor extraction, representative dense/attention/MoE weight samples, peak RSS/VRAM accounting, independent model logit parity, real Vulkan tile reuse and sustained TPS. A small compressed file is not proof of smaller peak inference memory.
