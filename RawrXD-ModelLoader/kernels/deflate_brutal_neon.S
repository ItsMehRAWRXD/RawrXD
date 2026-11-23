// AArch64 stored-block gzip encoder. Emits valid RFC 1952 framing and
// IEEE CRC32; stored DEFLATE blocks are intentionally non-compressing.
    .text
    .align  2
    .global deflate_brutal_neon
    .type   deflate_brutal_neon, %function
    .extern malloc
    .extern memcpy
    .extern rawrxd_gzip_crc32

deflate_brutal_neon:
    stp     x29, x30, [sp, #-16]!
    stp     x19, x20, [sp, #-16]!
    stp     x21, x22, [sp, #-16]!
    stp     x23, x24, [sp, #-16]!
    stp     x25, x26, [sp, #-16]!
    mov     x29, sp

    mov     x19, x0                 // original source
    mov     x20, x1                 // source length
    mov     x21, x2                 // out_len*
    cbz     x21, .Lfail
    str     xzr, [x21]
    cbz     x20, .Lsource_ok
    cbz     x19, .Lfail
.Lsource_ok:

    // blocks = max(1, ceil(len / 65535)); reject every size overflow.
    mov     x12, #65534
    adds    x11, x20, x12
    b.cs    .Lfail
    mov     x12, #65535
    udiv    x11, x11, x12
    cbnz    x11, .Lhave_blocks
    mov     x11, #1
.Lhave_blocks:
    mov     x13, #5
    mul     x14, x11, x13
    umulh   x15, x11, x13
    cbnz    x15, .Lfail
    adds    x14, x14, x20
    b.cs    .Lfail
    adds    x14, x14, #18
    b.cs    .Lfail

    mov     x0, x14
    bl      malloc
    cbz     x0, .Lfail
    mov     x22, x0                 // allocation base
    mov     x23, x0                 // output cursor
    mov     x24, x19                // source cursor

    // Gzip header.
    mov     w9, #0x8B1F
    strh    w9, [x23], #2
    mov     w9, #8
    strb    w9, [x23], #1
    str     wzr, [x23], #4
    strb    wzr, [x23], #1
    mov     w9, #3
    strb    w9, [x23], #1

    // Empty input still requires one final empty stored DEFLATE block.
    cbnz    x20, .Lblock_loop
    mov     w9, #1
    strb    w9, [x23], #1
    strh    wzr, [x23]
    mov     w9, #0xFFFF
    strh    w9, [x23, #2]
    add     x23, x23, #4
    b       .Lafter_blocks

.Lblock_loop:
    mov     x26, x20                // remaining bytes (preserved across memcpy)
.Lnext_block:
    cbz     x26, .Lafter_blocks
    mov     x11, #65535
    cmp     x26, x11
    csel    x25, x26, x11, ls       // chunk, preserved across memcpy
    cmp     x10, x25
    cset    w12, eq                 // BFINAL
    strb    w12, [x23], #1
    strh    w25, [x23]
    mvn     w12, w25
    strh    w12, [x23, #2]
    add     x23, x23, #4

    mov     x0, x23
    mov     x1, x24
    mov     x2, x25
    bl      memcpy
    add     x23, x23, x25
    add     x24, x24, x25
    sub     x26, x26, x25
    b       .Lnext_block

.Lafter_blocks:
    // Gzip trailer: IEEE CRC32(original source), then ISIZE modulo 2^32.
    mov     x0, x19
    mov     x1, x20
    bl      rawrxd_gzip_crc32
    str     w0, [x23], #4
    str     w20, [x23], #4
    sub     x9, x23, x22
    str     x9, [x21]
    mov     x0, x22
    b       .Lexit

.Lfail:
    mov     x0, xzr
.Lexit:
    ldp     x25, x26, [sp], #16
    ldp     x23, x24, [sp], #16
    ldp     x21, x22, [sp], #16
    ldp     x19, x20, [sp], #16
    ldp     x29, x30, [sp], #16
    ret
    .size deflate_brutal_neon, .-deflate_brutal_neon
