#include "codec/compression.h"

#include <cstdio>

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "zlib codec check failed at %d: %s\\n", __LINE__, #x); return 1; } } while (false)

int main() {
    bool ok = false;

    QByteArray binary;
    binary.reserve(256 * 1024);
    for (int i = 0; i < 256 * 1024; ++i)
        binary.append(static_cast<char>((i * 37) & 0xff));

    const QByteArray compressed = codec::deflate(binary, &ok);
    CHECK(ok && !compressed.isEmpty());
    CHECK(codec::inflate(compressed, &ok) == binary && ok);

    const QByteArray brutal = codec::deflate_brutal_masm(binary, &ok);
    CHECK(ok && !brutal.isEmpty());
    CHECK(codec::inflate(brutal, &ok) == binary && ok);

    // This expansion ratio exceeds the legacy 4x/10x buffer guesses.
    const QByteArray repetitive(1024 * 1024, 'R');
    const QByteArray compact = codec::deflate(repetitive, &ok);
    CHECK(ok && !compact.isEmpty());
    CHECK(compact.size() < 4096);
    CHECK(codec::inflate(compact, &ok) == repetitive && ok);

    const QByteArray overLimit = codec::inflate(compact, &ok, 1024);
    CHECK(!ok && overLimit.isEmpty());

    QByteArray truncated = compact;
    truncated.chop(1);
    CHECK(codec::inflate(truncated, &ok).isEmpty() && !ok);

    QByteArray trailing = compact;
    trailing.append('x');
    CHECK(codec::inflate(trailing, &ok).isEmpty() && !ok);

    const QByteArray invalid("not-a-zlib-stream");
    CHECK(codec::inflate(invalid, &ok).isEmpty() && !ok);

    const QByteArray empty;
    CHECK(codec::deflate(empty, &ok).isEmpty() && ok);
    CHECK(codec::inflate(empty, &ok).isEmpty() && ok);

    std::puts("QT_ZLIB_CODEC_ROUNDTRIP=PASS");
    return 0;
}
