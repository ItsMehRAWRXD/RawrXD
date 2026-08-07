// ============================================================================
// zlib_minimal.hpp - Minimal ZLIB ABI for Runtime Loading
// ============================================================================
// Zero-dependency header defining only the ZLIB functions we actually use.
// No linking against zlib.lib - loaded dynamically at runtime.
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

// ZLIB constants
#define Z_OK            0
#define Z_STREAM_END    1
#define Z_NEED_DICT     2
#define Z_ERRNO        (-1)
#define Z_STREAM_ERROR (-2)
#define Z_DATA_ERROR   (-3)
#define Z_MEM_ERROR    (-4)
#define Z_BUF_ERROR    (-5)
#define Z_VERSION_ERROR (-6)

#define Z_NO_FLUSH      0
#define Z_PARTIAL_FLUSH 1
#define Z_SYNC_FLUSH    2
#define Z_FULL_FLUSH    3
#define Z_FINISH        4
#define Z_BLOCK         5
#define Z_TREES         6

#define Z_DEFLATED      8

#define Z_DEFAULT_COMPRESSION  (-1)
#define Z_DEFAULT_STRATEGY     0

// Opaque ZLIB stream structure (minimal)
typedef struct z_stream_s {
    const uint8_t* next_in;
    uint32_t avail_in;
    uint32_t total_in;
    
    uint8_t* next_out;
    uint32_t avail_out;
    uint32_t total_out;
    
    const char* msg;
    void* state;
    void* zalloc;
    void* zfree;
    void* opaque;
    int data_type;
    uint32_t adler;
    uint32_t reserved;
} z_stream;

typedef z_stream* z_streamp;

// Function pointer types
typedef int (*pfn_deflateInit2)(z_streamp strm, int level, int method,
                                int windowBits, int memLevel, int strategy);
typedef int (*pfn_deflate)(z_streamp strm, int flush);
typedef int (*pfn_deflateEnd)(z_streamp strm);
typedef int (*pfn_inflateInit2)(z_streamp strm, int windowBits);
typedef int (*pfn_inflate)(z_streamp strm, int flush);
typedef int (*pfn_inflateEnd)(z_streamp strm);
typedef uint32_t (*pfn_adler32)(uint32_t adler, const uint8_t* buf, uint32_t len);
typedef uint32_t (*pfn_crc32)(uint32_t crc, const uint8_t* buf, uint32_t len);
typedef const char* (*pfn_zlibVersion)(void);

// Runtime function pointers (defined in zlib_loader.cpp)
extern pfn_deflateInit2 ZLIB_deflateInit2;
extern pfn_deflate ZLIB_deflate;
extern pfn_deflateEnd ZLIB_deflateEnd;
extern pfn_inflateInit2 ZLIB_inflateInit2;
extern pfn_inflate ZLIB_inflate;
extern pfn_inflateEnd ZLIB_inflateEnd;
extern pfn_adler32 ZLIB_adler32;
extern pfn_crc32 ZLIB_crc32;
extern pfn_zlibVersion ZLIB_zlibVersion;

// ============================================================================
// Runtime Loader API
// ============================================================================

namespace RawrXD {
namespace Compression {

// Load ZLIB DLL at runtime
// Returns true if ZLIB is available, false if using fallback
bool LoadZlibRuntime();

// Check if ZLIB is available
bool IsZlibAvailable();

// Get ZLIB version string (or "builtin" if using fallback)
const char* GetZlibVersion();

// Shutdown ZLIB runtime
void ShutdownZlibRuntime();

} // namespace Compression
} // namespace RawrXD

// ============================================================================
// Convenience macros (match ZLIB API)
// ============================================================================

#define deflateInit2(strm, level, method, windowBits, memLevel, strategy) \
    (ZLIB_deflateInit2 ? ZLIB_deflateInit2(strm, level, method, windowBits, memLevel, strategy) : Z_OK)

#define deflate(strm, flush) \
    (ZLIB_deflate ? ZLIB_deflate(strm, flush) : Z_STREAM_ERROR)

#define deflateEnd(strm) \
    (ZLIB_deflateEnd ? ZLIB_deflateEnd(strm) : Z_OK)

#define inflateInit2(strm, windowBits) \
    (ZLIB_inflateInit2 ? ZLIB_inflateInit2(strm, windowBits) : Z_OK)

#define inflate(strm, flush) \
    (ZLIB_inflate ? ZLIB_inflate(strm, flush) : Z_STREAM_ERROR)

#define inflateEnd(strm) \
    (ZLIB_inflateEnd ? ZLIB_inflateEnd(strm) : Z_OK)

#define adler32(adler, buf, len) \
    (ZLIB_adler32 ? ZLIB_adler32(adler, buf, len) : 0)

#define crc32(crc, buf, len) \
    (ZLIB_crc32 ? ZLIB_crc32(crc, buf, len) : 0)

#define zlibVersion() \
    (ZLIB_zlibVersion ? ZLIB_zlibVersion() : "builtin")
