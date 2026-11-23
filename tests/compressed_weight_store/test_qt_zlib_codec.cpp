// Standalone Qt/zlib regression for src/codec/compression.cpp.
// Build with Qt Core, zlib and the codec translation unit; fail closed on any mismatch.
#include <QByteArray>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <vector>
namespace codec {
QByteArray deflate(const QByteArray&, bool*);
QByteArray inflate(const QByteArray&, bool*);
QByteArray deflate_brutal_masm(const QByteArray&, bool*);
}
namespace {
bool check(bool value, const char* message) {
    if (!value) std::fprintf(stderr, "FAIL: %s\n", message);
    return value;
}
}
int main() {
    bool ok = false;
    QByteArray repetitive(65536, 'A');
    QByteArray packed = codec::deflate(repetitive, &ok);
    if (!check(ok && !packed.isEmpty(), "compress repetitive")) return 1;
    QByteArray decoded = codec::inflate(packed, &ok);
    if (!check(ok && decoded == repetitive, "high-ratio roundtrip")) return 2;
    QByteArray binary;
    binary.resize(65536);
    std::uint32_t state = 0x12345678u;
    for (int i = 0; i < binary.size(); ++i) {
        state ^= state << 13; state ^= state >> 17; state ^= state << 5;
        binary[i] = static_cast<char>(state & 255u);
    }
    packed = codec::deflate(binary, &ok);
    if (!check(ok && !packed.isEmpty(), "compress binary")) return 3;
    decoded = codec::inflate(packed, &ok);
    if (!check(ok && decoded == binary, "binary roundtrip")) return 4;
    QByteArray corrupted = packed;
    corrupted[corrupted.size() / 2] = static_cast<char>(corrupted[corrupted.size() / 2] ^ 0x7f);
    decoded = codec::inflate(corrupted, &ok);
    if (!check(!ok && decoded.isEmpty(), "corruption rejected")) return 5;
    QByteArray trailing = packed + QByteArray("junk");
    decoded = codec::inflate(trailing, &ok);
    if (!check(!ok && decoded.isEmpty(), "trailing input rejected")) return 6;
    QByteArray truncated = packed.left(packed.size() / 2);
    decoded = codec::inflate(truncated, &ok);
    if (!check(!ok && decoded.isEmpty(), "truncated input rejected")) return 7;
    QByteArray brutal = codec::deflate_brutal_masm(repetitive, &ok);
    if (!check(ok && !brutal.isEmpty(), "compatibility compression")) return 8;
    decoded = codec::inflate(brutal, &ok);
    if (!check(ok && decoded == repetitive, "compatibility roundtrip")) return 9;
    QByteArray empty;
    decoded = codec::inflate(empty, &ok);
    if (!check(ok && decoded.isEmpty(), "empty input")) return 10;
    std::puts("QT_ZLIB_CODEC_REGRESSION=PASS");
    return 0;
}
