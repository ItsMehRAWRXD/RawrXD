# RAWRPARITYG01 binary format

All integers are little-endian. Floats are IEEE-754 binary32 little-endian.
Strings are UTF-8 and encoded as `u64 byte_length` followed by raw bytes.

Header:
- 16 bytes magic: `RAWRPARITYG01\0\0\0`
- u32 version = 1
- u32 endian marker = 0x01020304
- string model_sha256 (lower-case hexadecimal)
- u64 model_bytes
- string architecture
- string prompt
- u64 prompt_token_count
- prompt_token_count * i32 prompt_token
- u64 step_count

Each step:
- i32 input_token
- i32 expected_top1
- u64 vocab_size
- vocab_size * f32 expected_logits

A producer does not need any RawrXD library. This is intentionally simple so a
separate trusted implementation can emit an independent golden and RawrXD can
verify it later with `--verify-golden`.
