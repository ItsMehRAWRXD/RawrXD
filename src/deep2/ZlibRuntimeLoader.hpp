// ============================================================================
// ZlibRuntimeLoader.hpp — Stub header
// ============================================================================
#pragma once

namespace RawrXD {
namespace Compression {

class ZlibRuntimeLoader {
public:
    ZlibRuntimeLoader();
    ~ZlibRuntimeLoader();

    bool Load();
    bool Decompress(unsigned char* out, unsigned int* outLen,
                    const unsigned char* in, unsigned int inLen);
};

} // namespace Compression
} // namespace RawrXD
