// ============================================================================
// zlib_runtime_loader.hpp - Runtime ZLIB Loader for RawrXD
// ============================================================================
// Zero-dependency runtime loading of zlib1.dll
// Compatible with brutal compression system for model streaming
// ============================================================================

#pragma once

#include <cstddef>
#include <cstdint>

#ifdef _WIN32
    #include <windows.h>
#else
    // Linux/macOS: Use dlopen for runtime loading
    #include <dlfcn.h>
    typedef void* HMODULE;
    #define LoadLibraryA(name) dlopen(name, RTLD_LAZY)
    #define GetProcAddress(handle, name) dlsym(handle, name)
    #define FreeLibrary(handle) dlclose(handle)
#endif

namespace RawrXD {
namespace Compression {

// ============================================================================
// ZLIB Function Pointer Types
// ============================================================================

typedef uint32_t (*pfn_zlibVersion)(void);
typedef int (*pfn_deflateInit2_)(void* strm, int level, int method, int windowBits,
                                  int memLevel, int strategy, const char* version,
                                  int stream_size);
typedef int (*pfn_deflate)(void* strm, int flush);
typedef int (*pfn_deflateEnd)(void* strm);
typedef int (*pfn_inflateInit2_)(void* strm, int windowBits, const char* version,
                                  int stream_size);
typedef int (*pfn_inflate)(void* strm, int flush);
typedef int (*pfn_inflateEnd)(void* strm);
typedef uint32_t (*pfn_crc32)(uint32_t crc, const uint8_t* buf, uint32_t len);
typedef uint32_t (*pfn_adler32)(uint32_t adler, const uint8_t* buf, uint32_t len);

// ============================================================================
// ZLIB Stream Structure (minimal)
// ============================================================================
#pragma pack(push, 1)
struct ZlibStream {
    const uint8_t* next_in;
    uint32_t avail_in;
    uint64_t total_in;
    uint8_t* next_out;
    uint32_t avail_out;
    uint64_t total_out;
    char* msg;
    void* state;
    void* zalloc;
    void* zfree;
    void* opaque;
    int data_type;
    uint64_t adler;
    uint64_t reserved;
};
#pragma pack(pop)

// ============================================================================
// Runtime ZLIB Loader
// ============================================================================
class ZlibRuntimeLoader {
public:
    ZlibRuntimeLoader();
    ~ZlibRuntimeLoader();

    // Load zlib1.dll at runtime
    bool Load();
    void Unload();
    bool IsLoaded() const;

    // Compression functions
    bool Compress(uint8_t* dest, uint32_t* destLen, const uint8_t* source, uint32_t sourceLen,
                  int level = 6);
    bool Decompress(uint8_t* dest, uint32_t* destLen, const uint8_t* source, uint32_t sourceLen);

    // Streaming compression (for model streaming)
    bool DeflateInit(ZlibStream* strm, int level, int windowBits = 15);
    bool Deflate(ZlibStream* strm, int flush);
    bool DeflateEnd(ZlibStream* strm);

    // Streaming decompression
    bool InflateInit(ZlibStream* strm, int windowBits = 15);
    bool Inflate(ZlibStream* strm, int flush);
    bool InflateEnd(ZlibStream* strm);

    // Checksum functions
    uint32_t CRC32(uint32_t crc, const uint8_t* buf, uint32_t len);
    uint32_t Adler32(uint32_t adler, const uint8_t* buf, uint32_t len);

    // Get version
    const char* GetVersion();

    // Error handling
    const char* GetLastError() const { return lastError_; }

private:
    HMODULE hZlib_;
    char lastError_[256];

    // Function pointers
    pfn_zlibVersion zlibVersion_;
    pfn_deflateInit2_ deflateInit2_;
    pfn_deflate deflate_;
    pfn_deflateEnd deflateEnd_;
    pfn_inflateInit2_ inflateInit2_;
    pfn_inflate inflate_;
    pfn_inflateEnd inflateEnd_;
    pfn_crc32 crc32_;
    pfn_adler32 adler32_;

    void SetError(const char* msg);
};

// ============================================================================
// Global Singleton Access
// ============================================================================
ZlibRuntimeLoader* GetZlibLoader();
bool InitializeZlibRuntime();
void ShutdownZlibRuntime();

// ============================================================================
// Convenience Functions
// ============================================================================
bool ZlibCompress(uint8_t* dest, uint32_t* destLen, const uint8_t* source, uint32_t sourceLen,
                  int level = 6);
bool ZlibDecompress(uint8_t* dest, uint32_t* destLen, const uint8_t* source, uint32_t sourceLen);
uint32_t ZlibCRC32(uint32_t crc, const uint8_t* buf, uint32_t len);

} // namespace Compression
} // namespace RawrXD
