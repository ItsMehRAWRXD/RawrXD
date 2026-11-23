// ============================================================================
// compression_core.cpp -- Qt-independent zlib compression core.
// ============================================================================
// See include/codec/compression_core.h for the contract.
//
// Format compatibility: compress() emits a standard zlib stream at
// Z_DEFAULT_COMPRESSION, byte-for-byte what the legacy codec::deflate produced.
// decompress() accepts any zlib stream, including those from the legacy
// codec::inflate and from third-party zlib producers.
// ============================================================================
#include "codec/compression_core.h"

#include <algorithm>
#include <cstring>
#include <limits>

// Build-time capability. CMake defines RAWRXD_HAVE_ZLIB=1 when a zlib provider
// is linked. A no-zlib build still compiles this translation unit and reports
// Status::Unsupported at call time, instead of failing to link.
#ifndef RAWRXD_HAVE_ZLIB
#define RAWRXD_HAVE_ZLIB 0
#endif

#if RAWRXD_HAVE_ZLIB
#include <zlib.h>
#endif

// ---------------------------------------------------------------------------
// Native, dependency-free fallback codec (RAWRXD_NATIVE_COMPRESSION_001).
//
// Used when this translation unit is built without zlib (RAWRXD_HAVE_ZLIB=0) so
// rawrxd_compression_core still provides real, bounded, byte-exact compression
// instead of an Unsupported stub. The format is self-describing and carries a
// checksum so corruption is detected rather than silently returning Ok.
//
//   header : 'R','X','D','N'  (4-byte magic, distinct from any zlib header)
//            varint original_size
//            uint32 checksum    (FNV-1a of the original bytes, little-endian)
//   body   : chunks until original_size bytes are produced
//            control <  0x80 : (control+1) literal bytes follow
//            control >= 0x80 : (control&0x7f)+1 copies of the next byte
//
// A zlib build still emits standard zlib streams from compress(); decompress()
// auto-detects this native magic so either producer decodes.
// ---------------------------------------------------------------------------
namespace rawrxd::compression {
namespace {

constexpr std::uint8_t kNativeMagic[4] = {'R', 'X', 'D', 'N'};

void PutVarint(std::vector<std::uint8_t>& out, std::uint64_t v) {
    while (v >= 0x80) {
        out.push_back(static_cast<std::uint8_t>(v) | 0x80);
        v >>= 7;
    }
    out.push_back(static_cast<std::uint8_t>(v));
}

bool GetVarint(const std::uint8_t* p, std::size_t n, std::size_t& pos,
               std::uint64_t& v) {
    v = 0;
    int shift = 0;
    while (pos < n) {
        const std::uint8_t b = p[pos++];
        v |= static_cast<std::uint64_t>(b & 0x7Fu) << shift;
        if ((b & 0x80u) == 0) return true;
        shift += 7;
        if (shift > 63) return false;
    }
    return false;
}

std::uint32_t Fnv1a(const std::uint8_t* d, std::size_t n) {
    std::uint32_t h = 2166136261u;
    for (std::size_t i = 0; i < n; ++i) {
        h ^= d[i];
        h *= 16777619u;
    }
    return h;
}

bool IsNativeStream(const std::uint8_t* d, std::size_t n) {
    return d != nullptr && n >= 4 &&
           d[0] == kNativeMagic[0] && d[1] == kNativeMagic[1] &&
           d[2] == kNativeMagic[2] && d[3] == kNativeMagic[3];
}

Result NativeCompress(const std::uint8_t* data, std::size_t size) {
    if (data == nullptr && size != 0) return {Status::InvalidInput, {}};
    Result out;
    out.status = Status::Ok;
    try {
        out.bytes.reserve(size / 2 + 16);
        out.bytes.insert(out.bytes.end(), kNativeMagic, kNativeMagic + 4);
        PutVarint(out.bytes, static_cast<std::uint64_t>(size));
        const std::uint32_t cs = Fnv1a(data, size);
        out.bytes.push_back(static_cast<std::uint8_t>(cs & 0xFFu));
        out.bytes.push_back(static_cast<std::uint8_t>((cs >> 8) & 0xFFu));
        out.bytes.push_back(static_cast<std::uint8_t>((cs >> 16) & 0xFFu));
        out.bytes.push_back(static_cast<std::uint8_t>((cs >> 24) & 0xFFu));
        std::size_t i = 0;
        while (i < size) {
            std::size_t run = 1;
            while (i + run < size && data[i + run] == data[i] && run < 128) ++run;
            if (run >= 3) {
                out.bytes.push_back(static_cast<std::uint8_t>(0x80u | (run - 1)));
                out.bytes.push_back(data[i]);
                i += run;
            } else {
                std::size_t lit = 0;
                while (i + lit < size && lit < 128) {
                    if (i + lit + 2 < size && data[i + lit] == data[i + lit + 1] &&
                        data[i + lit] == data[i + lit + 2])
                        break;
                    ++lit;
                }
                if (lit == 0) lit = 1;  // defensive; run>=3 handled above
                out.bytes.push_back(static_cast<std::uint8_t>(lit - 1));
                out.bytes.insert(out.bytes.end(), data + i, data + i + lit);
                i += lit;
            }
        }
    } catch (...) {
        return {Status::AllocationFailure, {}};
    }
    return out;
}

Result NativeDecompress(const std::uint8_t* data, std::size_t size,
                        std::size_t maxOutputBytes) {
    if (data == nullptr && size != 0) return {Status::InvalidInput, {}};
    if (!IsNativeStream(data, size)) return {Status::CorruptData, {}};
    std::size_t pos = 4;
    std::uint64_t origSize = 0;
    if (!GetVarint(data, size, pos, origSize)) return {Status::CorruptData, {}};
    if (origSize > maxOutputBytes) return {Status::OutputLimitExceeded, {}};
    if (size - pos < 4) return {Status::CorruptData, {}};
    const std::uint32_t expectCs =
        static_cast<std::uint32_t>(data[pos]) |
        (static_cast<std::uint32_t>(data[pos + 1]) << 8) |
        (static_cast<std::uint32_t>(data[pos + 2]) << 16) |
        (static_cast<std::uint32_t>(data[pos + 3]) << 24);
    pos += 4;
    Result out;
    out.status = Status::Ok;
    try {
        out.bytes.reserve(static_cast<std::size_t>(origSize));
    } catch (...) {
        return {Status::AllocationFailure, {}};
    }
    while (out.bytes.size() < origSize) {
        if (pos >= size) return {Status::CorruptData, {}};  // truncated
        const std::uint8_t ctrl = data[pos++];
        const std::size_t len =
            (ctrl & 0x80u) ? ((ctrl & 0x7Fu) + 1u)
                           : (static_cast<std::size_t>(ctrl) + 1u);
        if (out.bytes.size() + len > origSize) return {Status::CorruptData, {}};
        if (ctrl & 0x80u) {
            if (pos >= size) return {Status::CorruptData, {}};  // truncated run
            const std::uint8_t val = data[pos++];
            out.bytes.insert(out.bytes.end(), len, val);
        } else {
            if (size - pos < len) return {Status::CorruptData, {}};  // truncated literals
            out.bytes.insert(out.bytes.end(), data + pos, data + pos + len);
            pos += len;
        }
    }
    if (out.bytes.size() != origSize) return {Status::CorruptData, {}};
    if (Fnv1a(out.bytes.data(), out.bytes.size()) != expectCs)
        return {Status::CorruptData, {}};  // content corruption
    return out;
}

}  // namespace
}  // namespace rawrxd::compression

#if RAWRXD_HAVE_ZLIB

namespace rawrxd::compression {
namespace {

// zlib's one-shot entry points take uInt (32-bit) lengths. Anything larger has
// to be chunked, so report a clear error instead of silently truncating. The
// limit is exported in the header so callers can chunk proactively.
constexpr std::size_t kMaxOneShotBytes = MaxOneShotBytes;

// Growing buffer used while inflating. Starts at a small multiple of the input
// and doubles until it fits or the ceiling is hit, which avoids a second pass
// just to learn the output size.
class GrowBuf {
public:
    explicit GrowBuf(std::size_t cap) : cap_(cap) {}

    std::size_t capacity() const noexcept { return buf_.size(); }

    std::vector<std::uint8_t>& get() noexcept { return buf_; }

    bool grow() {
        if (buf_.size() >= cap_) return false;
        std::size_t next = buf_.empty() ? 4096 : buf_.size() * 2;
        next = std::min(next, cap_);
        try {
            buf_.resize(next);
        } catch (...) {
            return false;
        }
        return true;
    }

private:
    std::vector<std::uint8_t> buf_;
    std::size_t cap_;
};

} // namespace

Result compress(const std::uint8_t* data, std::size_t size, int level) {
    if (data == nullptr && size != 0) {
        return {Status::InvalidInput, {}};
    }

    // Empty input still produces a valid (2-byte header + empty deflate block +
    // adler32) zlib stream, which is what zlib does and what the legacy
    // adapter's callers observed.
    if (size > kMaxOneShotBytes) {
        return {Status::InvalidInput, {}};
    }

    uLongf bound = compressBound(static_cast<uLong>(size));
    if (bound == 0) {
        return {Status::BackendError, {}};
    }

    Result out;
    out.status = Status::Ok;
    try {
        out.bytes.resize(static_cast<std::size_t>(bound));
    } catch (...) {
        return {Status::AllocationFailure, {}};
    }

    const int rc = compress2(
        reinterpret_cast<Bytef*>(out.bytes.data()),
        &bound,
        reinterpret_cast<const Bytef*>(data),
        static_cast<uLong>(size),
        level);

    if (rc != Z_OK) {
        out.bytes.clear();
        // Z_BUF_ERROR / Z_MEM_ERROR map cleanly; anything else is a backend fault.
        if (rc == Z_MEM_ERROR) return {Status::AllocationFailure, {}};
        return {Status::BackendError, {}};
    }

    out.bytes.resize(static_cast<std::size_t>(bound));
    return out;
}

Result decompress(const std::uint8_t* data,
                  std::size_t size,
                  std::size_t maxOutputBytes) {
    if (data == nullptr && size != 0) {
        return {Status::InvalidInput, {}};
    }

    // RAWRXD_NATIVE_COMPRESSION_001: a native-fallback stream decodes here too,
    // so a zlib-enabled build can read payloads produced by a no-zlib build.
    if (IsNativeStream(data, size)) {
        return NativeDecompress(data, size, maxOutputBytes);
    }

    // Empty input: the legacy adapter returned success with empty output.
    if (size == 0) {
        Result out;
        out.status = Status::Ok;
        return out;
    }

    if (size > kMaxOneShotBytes) {
        return {Status::InvalidInput, {}};
    }

    if (maxOutputBytes == 0) {
        return {Status::OutputLimitExceeded, {}};
    }

    // Start at 4x the compressed size (the legacy adapter's first guess) and
    // grow under the caller's ceiling.
    std::size_t initial = size * 4;
    if (initial == 0) initial = 4096;
    initial = std::min(initial, maxOutputBytes);

    GrowBuf buf(maxOutputBytes);
    try {
        buf.get().resize(initial);
    } catch (...) {
        return {Status::AllocationFailure, {}};
    }

    for (;;) {
        uLongf produced = static_cast<uLongf>(buf.capacity());
        const int rc = uncompress(
            reinterpret_cast<Bytef*>(buf.get().data()),
            &produced,
            reinterpret_cast<const Bytef*>(data),
            static_cast<uLong>(size));

        if (rc == Z_OK) {
            Result out;
            out.status = Status::Ok;
            try {
                out.bytes.assign(buf.get().begin(),
                                 buf.get().begin() + static_cast<std::ptrdiff_t>(produced));
            } catch (...) {
                return {Status::AllocationFailure, {}};
            }
            return out;
        }

        if (rc == Z_BUF_ERROR) {
            // Output buffer too small. Grow, unless we are already at the cap.
            if (buf.capacity() >= maxOutputBytes) {
                return {Status::OutputLimitExceeded, {}};
            }
            if (!buf.grow()) {
                return {Status::AllocationFailure, {}};
            }
            continue;
        }

        // Z_DATA_ERROR: corrupt/truncated stream. Z_MEM_ERROR: allocation.
        if (rc == Z_MEM_ERROR) return {Status::AllocationFailure, {}};
        return {Status::CorruptData, {}};
    }
}

} // namespace rawrxd::compression

#else  // !RAWRXD_HAVE_ZLIB

// Explicit no-zlib implementation. This is deliberately NOT a silent no-op:
// every call reports Unsupported, so a caller can never mistake missing
// compression for data that passed through unchanged.
namespace rawrxd::compression {

// RAWRXD_NATIVE_COMPRESSION_001: without zlib, use the native fallback codec so
// compression is real, bounded and byte-exact instead of an Unsupported stub.
Result compress(const std::uint8_t* data, std::size_t size, int) {
    return NativeCompress(data, size);
}

Result decompress(const std::uint8_t* data, std::size_t size,
                  std::size_t maxOutputBytes) {
    return NativeDecompress(data, size, maxOutputBytes);
}

} // namespace rawrxd::compression

#endif  // RAWRXD_HAVE_ZLIB