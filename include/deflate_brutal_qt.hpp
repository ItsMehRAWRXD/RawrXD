#pragma once

// MASM-optimised "brutal" deflate: RFC 1952 gzip framing around DEFLATE
// stored blocks. The kernel (deflate_brutal_masm) is x64 MASM; this header is
// the C++ side.
//
// This header is consumed by BOTH Qt builds (compression_interface.cpp,
// gguf_loader.cpp's Qt consumers) and Qt-free builds (the Win32 IDE, the GGUF
// loader, the deep2 runtime). It therefore must not pull in Qt unconditionally:
// the Qt overloads are compiled only when QT_CORE_LIB is defined, and a
// std::vector<uint8_t> API is always available.

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "brutal_gzip.h"

#if defined(QT_CORE_LIB) || defined(Q_QDOC)
#include <QtCore/QByteArray>
#endif

namespace brutal {

/**
 * @brief Raw byte buffer used by the Qt-free API.
 */
using Bytes = std::vector<uint8_t>;

/**
 * @brief Compress a raw byte buffer using brutal MASM stored-block gzip
 * @param in Raw input data
 * @return Compressed gzip stream (RFC 1952 compliant)
 *
 * Ultra-fast, deterministic-size gzip compression using only stored blocks.
 * No Huffman, no LZ77 - pure memcpy speed with gzip framing.
 */
inline Bytes compress(const Bytes& in)
{
    if (in.empty()) return {};

    std::size_t packedSz = 0;
    void* p = deflate_brutal_masm(
        reinterpret_cast<const void*>(in.data()),
        in.size(),
        &packedSz
    );

    if (!p) return {};  // malloc failure

    Bytes out(static_cast<const uint8_t*>(p),
              static_cast<const uint8_t*>(p) + packedSz);
    std::free(p);
    return out;
}

/**
 * @brief Compress a raw pointer/size pair using brutal MASM stored-block gzip.
 */
inline Bytes compress(const void* data, std::size_t size)
{
    if (!data || size == 0) return {};

    std::size_t packedSz = 0;
    void* p = deflate_brutal_masm(data, size, &packedSz);

    if (!p) return {};

    Bytes out(static_cast<const uint8_t*>(p),
              static_cast<const uint8_t*>(p) + packedSz);
    std::free(p);
    return out;
}

/**
 * @brief Calculate worst-case compressed size for planning/allocation
 * @param rawSize Input size in bytes
 * @return Maximum possible compressed size (gzip header + stored blocks + footer)
 *
 * Formula: header(10) + ceil(rawSize/65535)*5 + rawSize + footer(8)
 */
inline std::size_t maxCompressedSize(std::size_t rawSize)
{
    std::size_t blockCount = (rawSize + 65534) / 65535;
    return 10 + (blockCount * 5) + rawSize + 8;
}

/**
 * @brief Skip the RFC 1952 gzip header, returning its length.
 *
 * Performs full bounds checking: an over-long/truncated header returns 0
 * instead of reading past the end of the buffer (the previous implementation
 * read data[header_size + 1] and walked NUL terminators without any bounds).
 */
inline std::size_t gzipHeaderSize(const uint8_t* data, std::size_t len)
{
    if (!data || len < 10) return 0;
    if (data[0] != 0x1f || data[1] != 0x8b) return 0;   // bad magic
    if (data[2] != 8) return 0;                          // not DEFLATE

    const uint8_t flg = data[3];
    std::size_t pos = 10;

    if (flg & 0x04) {                                    // FEXTRA
        if (pos + 2 > len) return 0;
        const std::size_t xlen = static_cast<std::size_t>(data[pos]) |
                                 (static_cast<std::size_t>(data[pos + 1]) << 8);
        pos += 2;
        if (xlen > len - pos) return 0;                  // bounds, no overflow
        pos += xlen;
    }
    if (flg & 0x08) {                                    // FNAME
        while (pos < len && data[pos] != 0) ++pos;
        if (pos >= len) return 0;                        // unterminated
        ++pos;
    }
    if (flg & 0x10) {                                    // FCOMMENT
        while (pos < len && data[pos] != 0) ++pos;
        if (pos >= len) return 0;                        // unterminated
        ++pos;
    }
    if (flg & 0x02) {                                    // FHCRC
        if (pos + 2 > len) return 0;
        pos += 2;
    }
    return pos;
}

/**
 * @brief Inflate a gzip stream produced by deflate_brutal_masm.
 *
 * Dependency-free: decoded from the raw DEFLATE stored-block stream rather
 * than relying on qUncompress, so it works in Qt-free builds and on any Qt
 * version. Returns an empty buffer if the input is not a valid brutal gzip
 * stream (bad header, non-stored block, truncated deflate data, missing
 * 8-byte gzip trailer).
 */
inline Bytes decompress(const Bytes& compressed)
{
    if (compressed.empty()) return {};

    const uint8_t* data = compressed.data();
    const std::size_t len = compressed.size();

    const std::size_t header = gzipHeaderSize(data, len);
    if (header == 0) return {};

    std::size_t pos = header;
    Bytes out;

    for (;;) {
        if (pos >= len) return {};                       // truncated
        const uint8_t blockHeader = data[pos++];
        if (blockHeader & 0x06) return {};               // not BTYPE=stored

        // Stored blocks skip to the next byte boundary.
        if (pos + 4 > len) return {};                    // truncated LEN/NLEN
        const std::size_t blockLen = static_cast<std::size_t>(data[pos]) |
                                     (static_cast<std::size_t>(data[pos + 1]) << 8);
        pos += 4;
        if (blockLen == 0) {
            // Empty final block: no payload, trailer follows immediately.
        } else {
            if (blockLen > len - pos) return {};         // truncated payload
            const std::size_t oldSize = out.size();
            out.resize(oldSize + blockLen);
            std::memcpy(out.data() + oldSize, data + pos, blockLen);
            pos += blockLen;
        }
        if (blockHeader & 0x01) break;                   // BFINAL
    }

    // Gzip trailer: CRC32 + ISIZE (8 bytes).
    if (pos + 8 > len) return {};

    const std::size_t isize = static_cast<std::size_t>(data[pos + 4]) |
                              (static_cast<std::size_t>(data[pos + 5]) << 8) |
                              (static_cast<std::size_t>(data[pos + 6]) << 16) |
                              (static_cast<std::size_t>(data[pos + 7]) << 24);
    if (isize != out.size()) return {};                  // corrupt ISIZE

    return out;
}

#if defined(QT_CORE_LIB) || defined(Q_QDOC)

/**
 * @brief Compress QByteArray using brutal MASM stored-block gzip
 * @param in Raw input data
 * @return Compressed gzip stream (RFC 1952 compliant)
 */
inline QByteArray compress(const QByteArray& in)
{
    if (in.isEmpty()) return {};

    std::size_t packedSz = 0;
    void* p = deflate_brutal_masm(
        reinterpret_cast<const void*>(in.constData()),
        static_cast<size_t>(in.size()),
        &packedSz
    );

    if (!p) return {};  // malloc failure

    QByteArray out(reinterpret_cast<const char*>(p), static_cast<int>(packedSz));
    std::free(p);
    return out;
}

/**
 * @brief Compress raw buffer using brutal MASM stored-block gzip
 */
inline QByteArray compress(const void* data, std::size_t size)
{
    if (!data || size == 0) return {};

    std::size_t packedSz = 0;
    void* p = deflate_brutal_masm(data, size, &packedSz);

    if (!p) return {};

    QByteArray out(reinterpret_cast<const char*>(p), static_cast<int>(packedSz));
    std::free(p);
    return out;
}

/**
 * @brief Decompress gzip stream using MASM inflate kernel
 */
inline QByteArray decompress(const QByteArray& compressed)
{
    if (compressed.isEmpty()) return {};

    const Bytes raw(reinterpret_cast<const uint8_t*>(compressed.constData()),
                    reinterpret_cast<const uint8_t*>(compressed.constData()) + compressed.size());
    const Bytes inflated = decompress(raw);
    if (inflated.empty()) return {};

    return QByteArray(reinterpret_cast<const char*>(inflated.data()),
                      static_cast<int>(inflated.size()));
}

#endif // QT_CORE_LIB

} // namespace brutal
