// ============================================================================
// ZlibRuntimeLoader.cpp — Stub implementation
// ============================================================================

#include "ZlibRuntimeLoader.hpp"

namespace RawrXD {
namespace Compression {

ZlibRuntimeLoader::ZlibRuntimeLoader() = default;
ZlibRuntimeLoader::~ZlibRuntimeLoader() = default;

bool ZlibRuntimeLoader::Load() {
    return false;
}

bool ZlibRuntimeLoader::Decompress(unsigned char* /*out*/, unsigned int* /*outLen*/,
                                    const unsigned char* /*in*/, unsigned int /*inLen*/) {
    return false;
}

} // namespace Compression
} // namespace RawrXD
