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

#include <zlib.h>

#include <algorithm>
#include <limits>

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