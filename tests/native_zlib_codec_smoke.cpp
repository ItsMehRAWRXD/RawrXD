#include "codec/compression.h"

#include <QByteArray>

#include <cstdio>
#include <cstring>

#define CHECK(expr) do { if (!(expr)) { \
    std::fprintf(stderr, "zlib smoke check failed at line %d: %s\\n", __LINE__, #expr); \
    return __LINE__; \
} } while (0)

int main() {
    bool ok = false;

    const QByteArray empty;
    const QByteArray emptyCompressed = codec::deflate(empty, &ok);
    CHECK(ok && emptyCompressed.isEmpty());
    const QByteArray emptyDecoded = codec::inflate(emptyCompressed, &ok);
    CHECK(ok && emptyDecoded.isEmpty());

    QByteArray repetitive(1024 * 1024, 'R');
    const QByteArray repetitiveCompressed = codec::deflate(repetitive, &ok);
    CHECK(ok && !repetitiveCompressed.isEmpty());
    CHECK(repetitiveCompressed.size() < repetitive.size() / 100);
    const QByteArray repetitiveDecoded = codec::inflate(repetitiveCompressed, &ok);
    CHECK(ok && repetitiveDecoded == repetitive);

    QByteArray binary(256 * 1024, Qt::Uninitialized);
    for (int i = 0; i < binary.size(); ++i)
        binary[i] = static_cast<char>((i * 73 + i / 7) & 0xff);
    const QByteArray binaryCompressed = codec::deflate_brutal_masm(binary, &ok);
    CHECK(ok && !binaryCompressed.isEmpty());
    CHECK(codec::inflate(binaryCompressed, &ok) == binary && ok);

    QByteArray truncated = repetitiveCompressed;
    truncated.chop(1);
    const QByteArray rejectedTruncated = codec::inflate(truncated, &ok);
    CHECK(!ok && rejectedTruncated.isEmpty());

    QByteArray trailing = repetitiveCompressed;
    trailing.append('!');
    const QByteArray rejectedTrailing = codec::inflate(trailing, &ok);
    CHECK(!ok && rejectedTrailing.isEmpty());

    std::puts("ZLIB_CODEC_SMOKE=PASS");
    return 0;
}
