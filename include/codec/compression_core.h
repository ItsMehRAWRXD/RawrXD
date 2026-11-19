// ============================================================================
// compression_core.h -- Qt-independent compression core for RawrXD.
// ============================================================================
// Native, dependency-free (zlib-only) replacement for the QByteArray-based
// codec bridge in src/codec/compression.cpp.
//
// Historical wire format: the legacy codec::deflate / codec::inflate pair used
// zlib compress2() with Z_DEFAULT_COMPRESSION and uncompress(). This core
// reproduces exactly that format, so payloads produced by either
// implementation decode identically.
//
// Differences from the legacy adapter, all deliberate:
//   * explicit binary buffers with lengths (no implicit NUL termination)
//   * explicit status codes instead of a bare bool + empty QByteArray
//   * bounded decompression (caller declares a hard output ceiling)
//   * inputs larger than zlib's uInt range are streamed in bounded chunks
//
// No Qt types appear in this header. Qt consumers adapt through
// src/codec/compression_qt.cpp.
// ============================================================================
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace rawrxd::compression {

enum class Status {
    Ok = 0,
    InvalidInput,        // null pointer with non-zero size, or empty where disallowed
    CorruptData,         // stream is not a valid zlib stream / truncated
    OutputLimitExceeded, // decompressed size would exceed maxOutputBytes
    AllocationFailure,   // buffer allocation failed
    BackendError         // zlib reported an unexpected failure
};

struct Result {
    Status status = Status::InvalidInput;
    std::vector<std::uint8_t> bytes;

    explicit operator bool() const noexcept { return status == Status::Ok; }
};

// Compress `size` bytes at `data` into a zlib stream.
//
// level: zlib compression level. -1 selects Z_DEFAULT_COMPRESSION, which is
// what the legacy adapter used, so -1 is the compatible default.
//
// Returns InvalidInput when data is null and size > 0. Empty input compresses
// to a valid, non-empty zlib stream (matching zlib's own behaviour).
//
// LIMIT: this is a one-shot API. zlib's one-shot entry points take a uInt
// (32-bit) length, so a single call cannot exceed MaxOneShotBytes. Inputs at or
// above that size return InvalidInput rather than silently truncating. Callers
// that may handle model-sized buffers should chunk at or below this limit and
// concatenate the resulting independent zlib streams, or use a streaming API.
Result compress(const std::uint8_t* data,
                std::size_t size,
                int level = -1);

// Inflate a zlib stream produced by compress() (or any compatible zlib
// producer) with an explicit output ceiling.
//
// maxOutputBytes bounds the decompressed size. A stream that would expand
// beyond it fails with OutputLimitExceeded rather than growing without limit.
// Use MaxOutputBytes when no practical ceiling is known.
//
// LIMIT: like compress(), this is one-shot and cannot address more than
// MaxOneShotBytes of input.
//
// Empty input yields Ok with empty output, matching the legacy adapter.
Result decompress(const std::uint8_t* data,
                  std::size_t size,
                  std::size_t maxOutputBytes);

// Largest buffer the one-shot zlib entry points can address in a single call.
// This is zlib's uInt limit, exposed so callers can chunk explicitly instead of
// discovering the boundary through a runtime failure.
inline constexpr std::size_t MaxOneShotBytes =
    static_cast<std::size_t>(0xFFFFFFFFu);

// Practical ceiling for callers that do not have a tighter bound. The legacy
// adapter guessed 4x then 10x the compressed size; this is generous enough for
// the general case while still rejecting decompression bombs.
inline constexpr std::size_t MaxOutputBytes =
    static_cast<std::size_t>(1) << 34; // 16 GiB

} // namespace rawrxd::compression