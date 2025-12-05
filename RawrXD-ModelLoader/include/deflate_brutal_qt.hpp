#pragma once
#include <cstdint>
#include <cstdlib>
#include <QtCore/QByteArray>
#include "brutal_gzip.h"
#include <zlib.h>

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

/**
 * @brief Decompress gzip stream using MASM inflate kernel
 * @param compressed Compressed gzip data
 * @return Decompressed raw data, empty if decompression fails
 * 
 * Fast decompression using MASM-optimized inflate algorithm.
 * Handles RFC 1952 gzip format with DEFLATE stored blocks.
 */
inline QByteArray decompress(const QByteArray& compressed)
{
    if (compressed.isEmpty()) return {};
    
    // Try to use MASM inflate if available; fallback to Qt's gzip decompression
    // For stored-block gzip, we can use standard zlib
    // The brutal format is RFC 1952 compliant, so standard tools work
    
    size_t max_uncompressed = compressed.size() * 4;  // Initial guess
    void* out_buf = malloc(max_uncompressed);
    if (!out_buf) return {};
    
    size_t out_len = 0;
    
#ifdef HAS_BRUTAL_INFLATE_MASM
    // Use MASM inflate if available
    extern "C" int inflate_brutal_masm(const void* src, size_t src_len, 
                                       void* dst, size_t dst_len, size_t* out_len);
    int result = inflate_brutal_masm(
        reinterpret_cast<const void*>(compressed.constData()),
        compressed.size(),
        out_buf,
        max_uncompressed,
        &out_len
    );
    
    if (result != 0) {
        free(out_buf);
        return {};
    }
#else
    // Fallback: use zlib (Qt's built-in gzip support)
    // Since brutal format is stored blocks, this is lossless
    z_stream stream{};
    stream.avail_in = compressed.size();
    stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(compressed.constData()));
    stream.avail_out = max_uncompressed;
    stream.next_out = reinterpret_cast<Bytef*>(out_buf);
    
    if (inflateInit2(&stream, 16 + MAX_WBITS) != Z_OK) {  // +16 for gzip header
        free(out_buf);
        return {};
    }
    
    int ret = inflate(&stream, Z_FINISH);
    out_len = stream.total_out;
    inflateEnd(&stream);
    
    if (ret != Z_STREAM_END) {
        free(out_buf);
        return {};
    }
#endif
    
    QByteArray result(reinterpret_cast<const char*>(out_buf), static_cast<int>(out_len));
    free(out_buf);
    return result;
}

} // namespace brutal
