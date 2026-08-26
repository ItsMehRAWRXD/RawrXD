// ============================================================================
// ZlibRuntimeLoader.cpp — Real implementation using Windows Compression API
// ============================================================================

#include "ZlibRuntimeLoader.hpp"
#include <windows.h>
#include <compressapi.h>
#include <cstring>

namespace RawrXD {
namespace Compression {

struct ZlibRuntimeLoader::Impl {
    COMPRESSOR_HANDLE compressor = nullptr;
    DECOMPRESSOR_HANDLE decompressor = nullptr;
    bool initialized = false;
};

ZlibRuntimeLoader::ZlibRuntimeLoader() : impl_(std::make_unique<Impl>()) {}
ZlibRuntimeLoader::~ZlibRuntimeLoader() {
    if (impl_) {
        if (impl_->compressor) CloseCompressor(impl_->compressor);
        if (impl_->decompressor) CloseDecompressor(impl_->decompressor);
    }
}

bool ZlibRuntimeLoader::Load() {
    if (!impl_) return false;
    // Create compressor (MSZIP = zlib-compatible)
    BOOL ok = CreateCompressor(COMPRESS_ALGORITHM_MSZIP, nullptr, &impl_->compressor);
    if (!ok) impl_->compressor = nullptr;
    // Create decompressor
    ok = CreateDecompressor(COMPRESS_ALGORITHM_MSZIP, nullptr, &impl_->decompressor);
    if (!ok) impl_->decompressor = nullptr;
    impl_->initialized = (impl_->compressor != nullptr && impl_->decompressor != nullptr);
    return impl_->initialized;
}

bool ZlibRuntimeLoader::Decompress(unsigned char* out, unsigned int* outLen,
                                    const unsigned char* in, unsigned int inLen) {
    if (!impl_ || !impl_->decompressor || !out || !outLen || !in) return false;
    SIZE_T destSize = *outLen;
    BOOL ok = ::Decompress(impl_->decompressor, in, inLen, out, destSize, &destSize);
    if (ok) {
        *outLen = static_cast<unsigned int>(destSize);
        return true;
    }
    return false;
}

bool ZlibRuntimeLoader::Compress(unsigned char* out, unsigned int* outLen,
                                  const unsigned char* in, unsigned int inLen) {
    if (!impl_ || !impl_->compressor || !out || !outLen || !in) return false;
    SIZE_T destSize = *outLen;
    BOOL ok = ::Compress(impl_->compressor, in, inLen, out, destSize, &destSize);
    if (ok) {
        *outLen = static_cast<unsigned int>(destSize);
        return true;
    }
    return false;
}

} // namespace Compression
} // namespace RawrXD
