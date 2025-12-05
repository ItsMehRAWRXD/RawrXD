#pragma once
#include <cstdint>
#include <cstdlib>
#include <QtCore/QByteArray>
#include "brutal_gzip.h"

namespace brutal {

/**
 * @brief Compress QByteArray using brutal MASM stored-block gzip
 * @param in Raw input data
 * @return Compressed gzip stream (RFC 1952 compliant)
 * 
 * Ultra-fast, deterministic-size gzip compression using only stored blocks.
 * No Huffman, no LZ77 – pure memcpy speed with gzip framing.
 * Perfect for GGUF tensor caching, streaming inference, or speed-critical paths.
 */
inline QByteArray compress(const QByteArray& in)
{
    if (in.isEmpty()) return {};
    
    std::uint64_t packedSz = 0;
    void* p = deflate_brutal_masm(
        reinterpret_cast<const void*>(in.constData()),
        in.size(),
        reinterpret_cast<size_t*>(&packedSz)
    );
    
    if (!p) return {};  // malloc failure
    
    QByteArray out(reinterpret_cast<const char*>(p), static_cast<int>(packedSz));
    std::free(p);
    return out;
}

/**
 * @brief Compress raw buffer using brutal MASM stored-block gzip
 * @param data Raw input pointer
 * @param size Input size in bytes
 * @return Compressed gzip stream (RFC 1952 compliant)
 */
inline QByteArray compress(const void* data, std::size_t size)
{
    if (!data || size == 0) return {};
    
    std::uint64_t packedSz = 0;
    void* p = deflate_brutal_masm(
        data,
        size,
        reinterpret_cast<size_t*>(&packedSz)
    );
    
    if (!p) return {};
    
    QByteArray out(reinterpret_cast<const char*>(p), static_cast<int>(packedSz));
    std::free(p);
    return out;
}

/**
 * @brief Calculate worst-case compressed size for planning/allocation
 * @param rawSize Input size
 * @return Maximum possible compressed size (gzip header + stored blocks + footer)
 * 
 * Formula: header(10) + ceil(rawSize/65535)*5 + rawSize + footer(8)
 */
inline std::size_t maxCompressedSize(std::size_t rawSize)
{
    std::size_t blockCount = (rawSize + 65534) / 65535;
    return 10 + (blockCount * 5) + rawSize + 8;
}

} // namespace brutal
