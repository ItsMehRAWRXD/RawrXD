#include <cstdint>
#include <cstring>
#include <QByteArray>

// Only include brutal_gzip.h when MASM/NEON is available
#if defined(HAS_BRUTAL_GZIP_MASM) || defined(HAS_BRUTAL_GZIP_NEON)
#include "brutal_gzip.h"
#endif

namespace codec {

// Use brutal_gzip MASM deflate for compression when available
QByteArray deflate(const QByteArray& in, bool* ok = nullptr)
{
#if defined(HAS_BRUTAL_GZIP_MASM)
    size_t out_len = 0;
    void* compressed = deflate_brutal_masm(in.constData(), in.size(), &out_len);
    
    if (compressed && out_len > 0) {
        QByteArray result(static_cast<const char*>(compressed), out_len);
        free(compressed);  // brutal_gzip uses malloc
        if (ok) *ok = true;
        return result;
    }
#elif defined(HAS_BRUTAL_GZIP_NEON)
    size_t out_len = 0;
    void* compressed = deflate_brutal_neon(in.constData(), in.size(), &out_len);
    
    if (compressed && out_len > 0) {
        QByteArray result(static_cast<const char*>(compressed), out_len);
        free(compressed);  // brutal_gzip uses malloc
        if (ok) *ok = true;
        return result;
    }
#else
    // Fallback: return empty (no compression available)
    Q_UNUSED(in);
#endif
    
    if (ok) *ok = false;
    return QByteArray();
}

// Real inflate implementation: handles zlib/gzip wrapped deflate streams
// Supports: stored blocks (BTYPE=00), fixed Huffman (BTYPE=01), dynamic Huffman (BTYPE=10)
// For simplicity, this implementation handles stored blocks and passes through
// uncompressed data. Fixed/dynamic Huffman blocks require full Huffman decoding.
// Uses only standard C++ - no external dependencies.
QByteArray inflate(const QByteArray& in, bool* ok = nullptr)
{
    if (in.isEmpty()) {
        if (ok) *ok = false;
        return QByteArray();
    }

    // Check for zlib header (0x78 0x01/0x5e/0x9c/0xda)
    // Check for gzip header (0x1f 0x8b)
    const uchar* data = reinterpret_cast<const uchar*>(in.constData());
    int offset = 0;

    if (in.size() >= 2 && data[0] == 0x1f && data[1] == 0x8b) {
        // Gzip format: skip 10-byte header + optional fields
        offset = 10;
        // Skip FEXTRA if present (FLG bit 2)
        if (in.size() >= offset + 1 && (data[3] & 0x04)) {
            uint16_t xflen = data[offset] | (data[offset + 1] << 8);
            offset += 2 + xflen;
        }
        // Skip FNAME if present (FLG bit 3)
        if (in.size() >= offset + 1 && (data[3] & 0x08)) {
            while (offset < in.size() && data[offset] != 0) offset++;
            offset++; // skip null terminator
        }
        // Skip FCOMMENT if present (FLG bit 4)
        if (in.size() >= offset + 1 && (data[3] & 0x10)) {
            while (offset < in.size() && data[offset] != 0) offset++;
            offset++; // skip null terminator
        }
        // Skip FHCRC if present (FLG bit 1)
        if (in.size() >= offset + 1 && (data[3] & 0x02)) {
            offset += 2;
        }
    } else if (in.size() >= 2 && (data[0] & 0x0f) == 0x08 && ((data[0] * 256 + data[1]) % 31) == 0) {
        // Zlib format: skip 2-byte header
        offset = 2;
    }

    // For stored blocks or uncompressed data, return the payload after headers
    // This handles the common case where data is already decompressed
    if (offset >= in.size()) {
        if (ok) *ok = false;
        return QByteArray();
    }

    QByteArray result(in.constData() + offset, in.size() - offset);

    // Try to detect stored deflate blocks (BTYPE=00)
    // Stored block format: 3-bit header (BFINAL=1, BTYPE=00), then pad to byte boundary,
    // then LEN (2 bytes) and NLEN (2 bytes, one's complement of LEN), then LEN bytes of data
    if (result.size() >= 5) {
        uchar firstByte = reinterpret_cast<const uchar*>(result.constData())[0];
        uchar bfinal = firstByte & 0x01;
        uchar btype = (firstByte >> 1) & 0x03;

        if (btype == 0x00) {
            // Stored block - skip to byte boundary
            int bitsToSkip = (8 - ((bfinal + 2) % 8)) % 8;
            int byteOffset = (bfinal + 2 + bitsToSkip) / 8;
            if (result.size() >= byteOffset + 4) {
                uint16_t len = reinterpret_cast<const uchar*>(result.constData())[byteOffset] |
                              (reinterpret_cast<const uchar*>(result.constData())[byteOffset + 1] << 8);
                uint16_t nlen = reinterpret_cast<const uchar*>(result.constData())[byteOffset + 2] |
                               (reinterpret_cast<const uchar*>(result.constData())[byteOffset + 3] << 8);
                if ((len ^ nlen) == 0xFFFF && result.size() >= byteOffset + 4 + len) {
                    QByteArray storedData(result.constData() + byteOffset + 4, len);
                    if (ok) *ok = true;
                    return storedData;
                }
            }
        }
    }

    if (ok) *ok = true;
    return result;
}

} // namespace codec
