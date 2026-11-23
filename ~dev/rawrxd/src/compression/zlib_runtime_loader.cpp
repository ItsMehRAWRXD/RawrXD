#include "zlib_runtime_loader.hpp"

#include <limits>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace RawrXD::Compression {

ZlibRuntimeLoader::~ZlibRuntimeLoader() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!library_) return;
#ifdef _WIN32
    FreeLibrary(static_cast<HMODULE>(library_));
#else
    dlclose(library_);
#endif
    library_ = nullptr;
    uncompress_ = nullptr;
    compress2_ = nullptr;
}

bool ZlibRuntimeLoader::Load() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (library_ && uncompress_ && compress2_) return true;

#ifdef _WIN32
    constexpr const char* candidates[] = {
        "zlib1.dll", "zlibwapi.dll", "zlib.dll"
    };
    for (const char* name : candidates) {
        HMODULE module = LoadLibraryA(name);
        if (!module) continue;
        auto uncompressFn = reinterpret_cast<UncompressFn>(
            GetProcAddress(module, "uncompress"));
        auto compressFn = reinterpret_cast<Compress2Fn>(
            GetProcAddress(module, "compress2"));
        if (uncompressFn && compressFn) {
            library_ = module;
            uncompress_ = uncompressFn;
            compress2_ = compressFn;
            return true;
        }
        FreeLibrary(module);
    }
#else
#if defined(__APPLE__)
    constexpr const char* candidates[] = {
        "libz.1.dylib", "libz.dylib"
    };
#else
    constexpr const char* candidates[] = {
        "libz.so.1", "libz.so"
    };
#endif
    for (const char* name : candidates) {
        void* module = dlopen(name, RTLD_NOW | RTLD_LOCAL);
        if (!module) continue;
        auto uncompressFn = reinterpret_cast<UncompressFn>(
            dlsym(module, "uncompress"));
        auto compressFn = reinterpret_cast<Compress2Fn>(
            dlsym(module, "compress2"));
        if (uncompressFn && compressFn) {
            library_ = module;
            uncompress_ = uncompressFn;
            compress2_ = compressFn;
            return true;
        }
        dlclose(module);
    }
#endif
    return false;
}

bool ZlibRuntimeLoader::IsLoaded() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return library_ && uncompress_ && compress2_;
}

bool ZlibRuntimeLoader::Decompress(std::uint8_t* out, std::uint32_t* outLen,
                                   const std::uint8_t* in,
                                   std::uint32_t inLen) noexcept {
    if (!outLen) return false;
    if (inLen == 0) {
        *outLen = 0;
        return true;
    }
    if (!out || !in) return false;

    std::lock_guard<std::mutex> lock(mutex_);
    if (!uncompress_) return false;

    unsigned long capacity = static_cast<unsigned long>(*outLen);
    const int result = uncompress_(
        out, &capacity, in, static_cast<unsigned long>(inLen));
    if (result != 0 || capacity > std::numeric_limits<std::uint32_t>::max())
        return false;

    *outLen = static_cast<std::uint32_t>(capacity);
    return true;
}

bool ZlibRuntimeLoader::Compress(std::uint8_t* out, std::uint32_t* outLen,
                                 const std::uint8_t* in, std::uint32_t inLen,
                                 int level) noexcept {
    if (!out || !outLen || (inLen && !in) || level < -1 || level > 9)
        return false;

    static constexpr std::uint8_t emptyInput = 0;
    const std::uint8_t* source = inLen ? in : &emptyInput;

    std::lock_guard<std::mutex> lock(mutex_);
    if (!compress2_) return false;

    unsigned long capacity = static_cast<unsigned long>(*outLen);
    const int result = compress2_(
        out, &capacity, source, static_cast<unsigned long>(inLen), level);
    if (result != 0 || capacity > std::numeric_limits<std::uint32_t>::max())
        return false;

    *outLen = static_cast<std::uint32_t>(capacity);
    return true;
}

} // namespace RawrXD::Compression
