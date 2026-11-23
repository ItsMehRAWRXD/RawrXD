#include "codec/compression.h"

#include <cstdio>
#include <initializer_list>

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

    // Boundary acceptance must be exact: the cap is inclusive, and the
    // streaming decoder must reject a one-byte-short cap across chunk edges.
    CHECK(codec::inflate(compact, &ok, repetitive.size()) == repetitive && ok);
    CHECK(codec::inflate(compact, &ok, repetitive.size() - 1).isEmpty() && !ok);
    CHECK(codec::inflate(compact, &ok, 0).isEmpty() && !ok);
    CHECK(codec::inflate(compact, &ok, -1).isEmpty() && !ok);

    // Exercise output sizes immediately around the 64 KiB inflate buffer.
    for (int size : {65535, 65536, 65537, 131073}) {
        const QByteArray source(size, 'B');
        const QByteArray packed = codec::deflate(source, &ok);
        CHECK(ok && !packed.isEmpty());
        CHECK(codec::inflate(packed, &ok, size) == source && ok);
        CHECK(codec::inflate(packed, &ok, size - 1).isEmpty() && !ok);
    }

    const QByteArray overLimit = codec::inflate(compact, &ok, 1024);
    CHECK(!ok && overLimit.isEmpty());

    QByteArray truncated = compact;
    truncated.chop(1);
    CHECK(codec::inflate(truncated, &ok).isEmpty() && !ok);

    QByteArray trailing = compact;
    trailing.append('x');
    CHECK(codec::inflate(trailing, &ok).isEmpty() && !ok);

    // Verify checksum rejection after a complete valid header and payload.
    // Flipping the Adler-32 trailer must never return unverified bytes.
    QByteArray badChecksum = compact;
    badChecksum[badChecksum.size() - 1] =
        static_cast<char>(badChecksum.at(badChecksum.size() - 1) ^ 0x01);
    CHECK(codec::inflate(badChecksum, &ok).isEmpty() && !ok);

    // Incompressible binary data may expand on disk; the decoder must still
    // reproduce every byte and respect the caller's exact output budget.
    QByteArray pseudoRandom;
    pseudoRandom.reserve(256 * 1024 + 17);
    unsigned int rng = 0x12345678u;
    for (int i = 0; i < 256 * 1024 + 17; ++i) {
        rng ^= rng << 13;
        rng ^= rng >> 17;
        rng ^= rng << 5;
        pseudoRandom.append(static_cast<char>(rng & 0xff));
    }
    const QByteArray randomPacked = codec::deflate(pseudoRandom, &ok);
    CHECK(ok && !randomPacked.isEmpty());
    CHECK(codec::inflate(randomPacked, &ok, pseudoRandom.size()) == pseudoRandom && ok);
    CHECK(codec::inflate(randomPacked, &ok, pseudoRandom.size() - 1).isEmpty() && !ok);

    const QByteArray invalid("not-a-zlib-stream");
    CHECK(codec::inflate(invalid, &ok).isEmpty() && !ok);

    const QByteArray empty;
    CHECK(codec::deflate(empty, &ok).isEmpty() && ok);
    CHECK(codec::inflate(empty, &ok).isEmpty() && ok);
    // Invalid limits must fail even when the compressed input is empty.
    CHECK(codec::inflate(empty, &ok, -1).isEmpty() && !ok);

    std::puts("QT_ZLIB_CODEC_ROUNDTRIP=PASS");
    return 0;
}
