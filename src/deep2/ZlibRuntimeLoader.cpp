// ============================================================================
// ZlibRuntimeLoader.cpp — Stub implementation (zlib not available on system)
// ============================================================================

#include "ZlibRuntimeLoader.hpp"
#include <cstring>

namespace RawrXD {
namespace Compression {

ZlibRuntimeLoader::ZlibRuntimeLoader() = default;
ZlibRuntimeLoader::~ZlibRuntimeLoader() = default;

bool ZlibRuntimeLoader::Load() {
    // zlib not available on this system — compression disabled
    return false;
}

bool ZlibRuntimeLoader::Decompress(unsigned char* /*out*/, unsigned int* /*outLen*/,
                                    const unsigned char* /*in*/, unsigned int /*inLen*/) {
    // zlib not available on this system — compression disabled
    return false;
}

} // namespace Compression
} // namespace RawrXD
