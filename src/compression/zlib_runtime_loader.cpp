// ============================================================================
// zlib_runtime_loader.cpp - Runtime ZLIB Loader Implementation
// ============================================================================
// Zero-dependency runtime loading of zlib1.dll
// Compatible with brutal compression system for model streaming
// ============================================================================

#include "zlib_runtime_loader.hpp"
#include <cstring>

namespace RawrXD {
namespace Compression {

// ============================================================================
// ZLIB Constants
// ============================================================================
#define Z_NO_FLUSH      0
#define Z_PARTIAL_FLUSH 1
#define Z_SYNC_FLUSH    2
#define Z_FULL_FLUSH    3
#define Z_FINISH        4

#define Z_OK            0
#define Z_STREAM_END    1
#define Z_NEED_DICT     2
#define Z_ERRNO        (-1)
#define Z_STREAM_ERROR (-2)
#define Z_DATA_ERROR   (-3)
#define Z_MEM_ERROR    (-4)
#define Z_BUF_ERROR    (-5)
#define Z_VERSION_ERROR (-6)

// ============================================================================
// Constructor / Destructor
// ============================================================================
ZlibRuntimeLoader::ZlibRuntimeLoader()
    : hZlib_(nullptr)
    , zlibVersion_(nullptr)
    , deflateInit2_(nullptr)
    , deflate_(nullptr)
    , deflateEnd_(nullptr)
    , inflateInit2_(nullptr)
    , inflate_(nullptr)
    , inflateEnd_(nullptr)
    , crc32_(nullptr)
    , adler32_(nullptr)
{
    lastError_[0] = '\0';
}

ZlibRuntimeLoader::~ZlibRuntimeLoader()
{
    Unload();
}

// ============================================================================
// Load / Unload
// ============================================================================
bool ZlibRuntimeLoader::Load()
{
    if (hZlib_) {
        return true; // Already loaded
    }

    // Try to load zlib1.dll
    hZlib_ = LoadLibraryA("zlib1.dll");
    if (!hZlib_) {
        // Try alternative names
        hZlib_ = LoadLibraryA("zlib.dll");
        if (!hZlib_) {
            hZlib_ = LoadLibraryA("libz.dll");
            if (!hZlib_) {
                SetError("Failed to load zlib1.dll (or alternatives)");
                return false;
            }
        }
    }

    // Get function pointers
    zlibVersion_ = (pfn_zlibVersion)GetProcAddress(hZlib_, "zlibVersion");
    deflateInit2_ = (pfn_deflateInit2_)GetProcAddress(hZlib_, "deflateInit2_");
    deflate_ = (pfn_deflate)GetProcAddress(hZlib_, "deflate");
    deflateEnd_ = (pfn_deflateEnd)GetProcAddress(hZlib_, "deflateEnd");
    inflateInit2_ = (pfn_inflateInit2_)GetProcAddress(hZlib_, "inflateInit2_");
    inflate_ = (pfn_inflate)GetProcAddress(hZlib_, "inflate");
    inflateEnd_ = (pfn_inflateEnd)GetProcAddress(hZlib_, "inflateEnd");
    crc32_ = (pfn_crc32)GetProcAddress(hZlib_, "crc32");
    adler32_ = (pfn_adler32)GetProcAddress(hZlib_, "adler32");

    // Verify critical functions
    if (!deflateInit2_ || !deflate_ || !deflateEnd_ ||
        !inflateInit2_ || !inflate_ || !inflateEnd_) {
        SetError("Failed to resolve critical ZLIB functions");
        Unload();
        return false;
    }

    return true;
}

void ZlibRuntimeLoader::Unload()
{
    if (hZlib_) {
        FreeLibrary(hZlib_);
        hZlib_ = nullptr;
    }

    zlibVersion_ = nullptr;
    deflateInit2_ = nullptr;
    deflate_ = nullptr;
    deflateEnd_ = nullptr;
    inflateInit2_ = nullptr;
    inflate_ = nullptr;
    inflateEnd_ = nullptr;
    crc32_ = nullptr;
    adler32_ = nullptr;
}

bool ZlibRuntimeLoader::IsLoaded() const
{
    return hZlib_ != nullptr;
}

// ============================================================================
// Simple Compression / Decompression
// ============================================================================
bool ZlibRuntimeLoader::Compress(uint8_t* dest, uint32_t* destLen,
                                  const uint8_t* source, uint32_t sourceLen,
                                  int level)
{
    if (!IsLoaded()) {
        SetError("ZLIB not loaded");
        return false;
    }

    ZlibStream strm = {};
    strm.next_in = source;
    strm.avail_in = sourceLen;
    strm.next_out = dest;
    strm.avail_out = *destLen;

    // Initialize
    int ret = deflateInit2_(&strm, level, 8, 15, 8, 0, "1.2.11", sizeof(ZlibStream));
    if (ret != Z_OK) {
        SetError("deflateInit2_ failed");
        return false;
    }

    // Compress
    ret = deflate_(&strm, Z_FINISH);
    if (ret != Z_STREAM_END) {
        deflateEnd_(&strm);
        SetError("deflate failed");
        return false;
    }

    *destLen = strm.total_out;
    deflateEnd_(&strm);
    return true;
}

bool ZlibRuntimeLoader::Decompress(uint8_t* dest, uint32_t* destLen,
                                    const uint8_t* source, uint32_t sourceLen)
{
    if (!IsLoaded()) {
        SetError("ZLIB not loaded");
        return false;
    }

    ZlibStream strm = {};
    strm.next_in = source;
    strm.avail_in = sourceLen;
    strm.next_out = dest;
    strm.avail_out = *destLen;

    // Initialize
    int ret = inflateInit2_(&strm, 15, "1.2.11", sizeof(ZlibStream));
    if (ret != Z_OK) {
        SetError("inflateInit2_ failed");
        return false;
    }

    // Decompress
    ret = inflate_(&strm, Z_FINISH);
    if (ret != Z_STREAM_END) {
        inflateEnd_(&strm);
        SetError("inflate failed");
        return false;
    }

    *destLen = strm.total_out;
    inflateEnd_(&strm);
    return true;
}

// ============================================================================
// Streaming Compression
// ============================================================================
bool ZlibRuntimeLoader::DeflateInit(ZlibStream* strm, int level, int windowBits)
{
    if (!IsLoaded()) {
        SetError("ZLIB not loaded");
        return false;
    }

    int ret = deflateInit2_(strm, level, 8, windowBits, 8, 0, "1.2.11", sizeof(ZlibStream));
    return ret == Z_OK;
}

bool ZlibRuntimeLoader::Deflate(ZlibStream* strm, int flush)
{
    if (!IsLoaded() || !deflate_) {
        return false;
    }

    int ret = deflate_(strm, flush);
    return ret == Z_OK || ret == Z_STREAM_END;
}

bool ZlibRuntimeLoader::DeflateEnd(ZlibStream* strm)
{
    if (!IsLoaded() || !deflateEnd_) {
        return false;
    }

    int ret = deflateEnd_(strm);
    return ret == Z_OK;
}

// ============================================================================
// Streaming Decompression
// ============================================================================
bool ZlibRuntimeLoader::InflateInit(ZlibStream* strm, int windowBits)
{
    if (!IsLoaded()) {
        SetError("ZLIB not loaded");
        return false;
    }

    int ret = inflateInit2_(strm, windowBits, "1.2.11", sizeof(ZlibStream));
    return ret == Z_OK;
}

bool ZlibRuntimeLoader::Inflate(ZlibStream* strm, int flush)
{
    if (!IsLoaded() || !inflate_) {
        return false;
    }

    int ret = inflate_(strm, flush);
    return ret == Z_OK || ret == Z_STREAM_END;
}

bool ZlibRuntimeLoader::InflateEnd(ZlibStream* strm)
{
    if (!IsLoaded() || !inflateEnd_) {
        return false;
    }

    int ret = inflateEnd_(strm);
    return ret == Z_OK;
}

// ============================================================================
// Checksum Functions
// ============================================================================
uint32_t ZlibRuntimeLoader::CRC32(uint32_t crc, const uint8_t* buf, uint32_t len)
{
    if (!IsLoaded() || !crc32_) {
        return 0;
    }
    return crc32_(crc, buf, len);
}

uint32_t ZlibRuntimeLoader::Adler32(uint32_t adler, const uint8_t* buf, uint32_t len)
{
    if (!IsLoaded() || !adler32_) {
        return 0;
    }
    return adler32_(adler, buf, len);
}

// ============================================================================
// Version
// ============================================================================
const char* ZlibRuntimeLoader::GetVersion()
{
    if (!IsLoaded() || !zlibVersion_) {
        return "unknown";
    }
    return zlibVersion_();
}

// ============================================================================
// Error Handling
// ============================================================================
void ZlibRuntimeLoader::SetError(const char* msg)
{
    strncpy(lastError_, msg, sizeof(lastError_) - 1);
    lastError_[sizeof(lastError_) - 1] = '\0';
}

// ============================================================================
// Global Singleton
// ============================================================================
static ZlibRuntimeLoader* g_zlibLoader = nullptr;

ZlibRuntimeLoader* GetZlibLoader()
{
    return g_zlibLoader;
}

bool InitializeZlibRuntime()
{
    if (g_zlibLoader) {
        return true;
    }

    g_zlibLoader = new ZlibRuntimeLoader();
    if (!g_zlibLoader->Load()) {
        delete g_zlibLoader;
        g_zlibLoader = nullptr;
        return false;
    }

    return true;
}

void ShutdownZlibRuntime()
{
    if (g_zlibLoader) {
        delete g_zlibLoader;
        g_zlibLoader = nullptr;
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================
bool ZlibCompress(uint8_t* dest, uint32_t* destLen, const uint8_t* source,
                   uint32_t sourceLen, int level)
{
    ZlibRuntimeLoader loader;
    if (!loader.Load()) {
        return false;
    }
    return loader.Compress(dest, destLen, source, sourceLen, level);
}

bool ZlibDecompress(uint8_t* dest, uint32_t* destLen, const uint8_t* source,
                     uint32_t sourceLen)
{
    ZlibRuntimeLoader loader;
    if (!loader.Load()) {
        return false;
    }
    return loader.Decompress(dest, destLen, source, sourceLen);
}

uint32_t ZlibCRC32(uint32_t crc, const uint8_t* buf, uint32_t len)
{
    ZlibRuntimeLoader loader;
    if (!loader.Load()) {
        return 0;
    }
    return loader.CRC32(crc, buf, len);
}

} // namespace Compression
} // namespace RawrXD
