#pragma once
#include <cstdint>
#include <cstdlib>
#include <vector>
#include "brutal_gzip.h"

namespace brutal {

/**
 * @brief Compress raw buffer using brutal MASM stored-block gzip
 * @param in Raw input data
 * @return Compressed gzip stream (RFC 1952 compliant)
 *
 * Ultra-fast, deterministic-size gzip compression using only stored blocks.
 * No Huffman, no LZ77 - pure memcpy speed with gzip framing.
 * Perfect for GGUF tensor caching, streaming inference, or speed-critical paths.
 */
inline std::vector<uint8_t> compress(const std::vector<uint8_t>& in)
{
    if (in.empty()) return {};

    std::uint64_t packedSz = 0;
    void* p = deflate_brutal_masm(
        reinterpret_cast<const void*>(in.data()),
        in.size(),
        reinterpret_cast<size_t*>(&packedSz)
    );

    if (!p) return {};  // malloc failure

    std::vector<uint8_t> out(static_cast<const uint8_t*>(p),
                             static_cast<const uint8_t*>(p) + packedSz);
    std::free(p);
    return out;
}

/**
 * @brief Compress raw buffer using brutal MASM stored-block gzip
 * @param data Raw input pointer
 * @param size Input size in bytes
 * @return Compressed gzip stream (RFC 1952 compliant)
 */
inline std::vector<uint8_t> compress(const void* data, std::size_t size)
{
    if (!data || size == 0) return {};

    std::uint64_t packedSz = 0;
    void* p = deflate_brutal_masm(
        data,
        size,
        reinterpret_cast<size_t*>(&packedSz)
    );

    if (!p) return {};

    std::vector<uint8_t> out(static_cast<const uint8_t*>(p),
                             static_cast<const uint8_t*>(p) + packedSz);
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
 * @brief Decompress gzip stream (stored-block deflate)
 * @param compressed Compressed gzip data
 * @return Decompressed raw data, empty if decompression fails
 *
 * Handles RFC 1952 gzip format with DEFLATE stored blocks.
 * Uses MASM inflate when available; otherwise parses stored blocks directly.
 */
inline std::vector<uint8_t> decompress(const std::vector<uint8_t>& compressed)
{
    if (compressed.empty()) return {};

#ifdef HAS_BRUTAL_INFLATE_MASM
    extern "C" int inflate_brutal_masm(const void* src, size_t src_len,
                                       void* dst, size_t dst_len, size_t* out_len);
    size_t max_uncompressed = compressed.size() * 4;
    std::vector<uint8_t> out_buf(max_uncompressed);
    size_t out_len = 0;
    int result = inflate_brutal_masm(
        reinterpret_cast<const void*>(compressed.data()),
        compressed.size(),
        reinterpret_cast<void*>(out_buf.data()),
        max_uncompressed,
        &out_len
    );
    if (result != 0) return {};
    out_buf.resize(out_len);
    return out_buf;
#else
    // Fallback: parse gzip header and extract stored-block deflate data
    const unsigned char* data = compressed.data();
    size_t data_len = compressed.size();

    if (data_len < 18) return {};  // Minimum: 10-byte header + data + 8-byte footer

    // Verify gzip magic number
    if (data[0] != 0x1f || data[1] != 0x8b) return {};

    // Skip to deflate data (skip variable-length gzip header)
    size_t header_size = 10;
    if (data[3] & 0x04) {  // FEXTRA flag
        header_size += 2 + (data[header_size] | (data[header_size + 1] << 8));
    }
    if (data[3] & 0x08) {  // FNAME flag
        while (header_size < data_len && data[header_size] != 0) header_size++;
        header_size++;
    }
    if (data[3] & 0x10) {  // FCOMMENT flag
        while (header_size < data_len && data[header_size] != 0) header_size++;
        header_size++;
    }
    if (data[3] & 0x02) {  // FHCRC flag
        header_size += 2;
    }

    // Extract raw deflate data (without 8-byte gzip footer)
    size_t deflate_len = data_len - header_size - 8;
    const unsigned char* deflate_data = data + header_size;

    // Parse stored-block deflate stream
    std::vector<uint8_t> out;
    size_t pos = 0;
    while (pos < deflate_len) {
        if (pos + 5 > deflate_len) return {};  // Truncated block header
        unsigned char block_hdr = deflate_data[pos++];
        // BFINAL = bit 0, BTYPE = bits 1-2 (must be 00 for stored)
        if ((block_hdr & 0x06) != 0x00) return {};  // Not a stored block
        uint16_t len = static_cast<uint16_t>(deflate_data[pos]) |
                       (static_cast<uint16_t>(deflate_data[pos + 1]) << 8);
        pos += 4;  // Skip LEN + NLEN
        if (pos + len > deflate_len) return {};  // Truncated block data
        out.insert(out.end(), deflate_data + pos, deflate_data + pos + len);
        pos += len;
        if (block_hdr & 0x01) break;  // BFINAL set
    }
    return out;
#endif
}

} // namespace brutal
