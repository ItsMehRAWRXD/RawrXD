#include "codec/compression.h"
#include <cstdio>
#include <cstdlib>

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "zlib codec check failed at %d: %s\\n", __LINE__, #x); return 1; } } while (false)

int main() {
    QByteArray input;
    input.reserve(256 * 1024);
    for (int i = 0; i < 256 * 1024; ++i)
        input.append(static_cast<char>((i * 37) & 0xff));

    bool ok = false;
    const auto compressed = codec::deflate(input, &ok);
    CHECK(ok && !compressed.isEmpty());
    const auto decoded = codec::inflate(compressed, &ok);
    CHECK(ok && decoded == input);

    const auto brutal = codec::deflate_brutal_masm(input, &ok);
    CHECK(ok && !brutal.isEmpty());
    const auto brutalDecoded = codec::inflate(brutal, &ok);
    CHECK(ok && brutalDecoded == input);

    const QByteArray empty;
    const auto emptyCompressed = codec::deflate(empty, &ok);
    CHECK(ok && emptyCompressed.isEmpty());
    const auto emptyDecoded = codec::inflate(emptyCompressed, &ok);
    CHECK(ok && emptyDecoded.isEmpty());

    const QByteArray invalid("not-a-zlib-stream");
    const auto rejected = codec::inflate(invalid, &ok);
    CHECK(!ok && rejected.isEmpty());

    std::puts("QT_ZLIB_CODEC_ROUNDTRIP=PASS");
    return 0;
}
