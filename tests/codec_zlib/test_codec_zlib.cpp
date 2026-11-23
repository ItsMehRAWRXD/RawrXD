#include "codec/compression.h"
#include <QByteArray>
#include <cassert>
#include <cstdint>
#include <iostream>

int main() {
    bool ok = false;
    const QByteArray repetitive(65536, 'A');
    const QByteArray packed = codec::deflate(repetitive, &ok);
    assert(ok && !packed.isEmpty() && packed.size() < repetitive.size());
    assert(codec::inflate(packed, &ok) == repetitive && ok);

    QByteArray binary;
    for (int i = 0; i < 65536; ++i) binary.append(static_cast<char>((i * 73 + i / 251) & 255));
    const auto binaryPacked = codec::deflate_brutal_masm(binary, &ok);
    assert(ok && codec::inflate(binaryPacked, &ok) == binary && ok);

    QByteArray truncated = packed.left(packed.size() - 1);
    codec::inflate(truncated, &ok);
    assert(!ok);

    QByteArray trailing = packed + QByteArray("junk");
    codec::inflate(trailing, &ok);
    assert(!ok);

    QByteArray corrupt = packed;
    corrupt[corrupt.size() / 2] = static_cast<char>(corrupt[corrupt.size() / 2] ^ 0x7f);
    codec::inflate(corrupt, &ok);
    assert(!ok);

    assert(codec::inflate(QByteArray(), &ok).isEmpty() && ok);
    std::cout << "codec zlib streaming tests passed\n";
}
