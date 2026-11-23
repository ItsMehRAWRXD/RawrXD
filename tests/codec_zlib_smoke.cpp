#include "codec/compression.h"

#include <cstdio>
#include <cstdint>

namespace {
int fail(const char* message) {
    std::fprintf(stderr, "codec zlib smoke failed: %s\n", message);
    return 1;
}
}

int main() {
    QByteArray repetitive(65536, 'R');
    bool ok = false;
    const QByteArray compressed = codec::deflate(repetitive, &ok);
    if (!ok || compressed.isEmpty()) return fail("default deflate");
    const QByteArray restored = codec::inflate(compressed, &ok);
    if (!ok || restored != repetitive) return fail("default inflate roundtrip");

    QByteArray binary;
    binary.reserve(65536);
    for (int i = 0; i < 256; ++i)
        for (int j = 0; j < 256; ++j)
            binary.append(static_cast<char>(i));
    const QByteArray binaryCompressed = codec::deflate(binary, &ok);
    if (!ok || binaryCompressed.isEmpty()) return fail("binary deflate");
    if (codec::inflate(binaryCompressed, &ok) != binary || !ok)
        return fail("binary inflate roundtrip");

    QByteArray truncated = compressed;
    truncated.chop(1);
    (void)codec::inflate(truncated, &ok);
    if (ok) return fail("truncated stream accepted");

    QByteArray trailing = compressed;
    trailing.append('\0');
    (void)codec::inflate(trailing, &ok);
    if (ok) return fail("trailing bytes accepted");

    const QByteArray maximum = codec::deflate_brutal_masm(repetitive, &ok);
    if (!ok || maximum.isEmpty()) return fail("maximum-level zlib fallback");
    if (codec::inflate(maximum, &ok) != repetitive || !ok)
        return fail("maximum-level roundtrip");

    const QByteArray empty;
    if (!codec::deflate(empty, &ok).isEmpty() || !ok)
        return fail("empty deflate");
    if (!codec::inflate(empty, &ok).isEmpty() || !ok)
        return fail("empty inflate");

    std::puts("codec zlib smoke: PASS");
    return 0;
}
