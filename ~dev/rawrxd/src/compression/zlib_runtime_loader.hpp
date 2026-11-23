#pragma once

#include <cstdint>
#include <mutex>

namespace RawrXD::Compression {

// Runtime-loaded zlib adapter. No zlib headers or link-time zlib dependency
// are required by consumers; the system zlib ABI is resolved at runtime.
class ZlibRuntimeLoader {
public:
    ZlibRuntimeLoader() = default;
    ~ZlibRuntimeLoader();

    ZlibRuntimeLoader(const ZlibRuntimeLoader&) = delete;
    ZlibRuntimeLoader& operator=(const ZlibRuntimeLoader&) = delete;

    bool Load() noexcept;
    bool IsLoaded() const noexcept;

    // outLen is input capacity and is replaced with bytes written on success.
    bool Decompress(std::uint8_t* out, std::uint32_t* outLen,
                    const std::uint8_t* in, std::uint32_t inLen) noexcept;

    // outLen is input capacity and is replaced with bytes written on success.
    bool Compress(std::uint8_t* out, std::uint32_t* outLen,
                  const std::uint8_t* in, std::uint32_t inLen,
                  int level = 6) noexcept;

private:
#if defined(_WIN32) && defined(_M_IX86)
    using UncompressFn = int(__cdecl*)(unsigned char*, unsigned long*,
                                       const unsigned char*, unsigned long);
    using Compress2Fn = int(__cdecl*)(unsigned char*, unsigned long*,
                                      const unsigned char*, unsigned long, int);
#else
    using UncompressFn = int(*)(unsigned char*, unsigned long*,
                                const unsigned char*, unsigned long);
    using Compress2Fn = int(*)(unsigned char*, unsigned long*,
                               const unsigned char*, unsigned long, int);
#endif

    mutable std::mutex mutex_;
    void* library_ = nullptr;
    UncompressFn uncompress_ = nullptr;
    Compress2Fn compress2_ = nullptr;
};

} // namespace RawrXD::Compression
