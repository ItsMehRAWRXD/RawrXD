// Legacy NEON entry point retained for existing callers. Reuse the
// validated AArch64 stored-block gzip implementation so CRC32, empty input,
// overflow checks, and multi-block final flags cannot drift between kernels.
    .text
    .align  2
    .global deflate_neon
    .type   deflate_neon, %function
    .extern deflate_brutal_neon

deflate_neon:
    b       deflate_brutal_neon
    .size deflate_neon, .-deflate_neon
