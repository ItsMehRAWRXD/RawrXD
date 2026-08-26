// ============================================================================
// ZlibRuntimeLoader.hpp — Windows Compression API wrapper
// ============================================================================
#pragma once
#include <memory>

namespace RawrXD {
namespace Compression {

class ZlibRuntimeLoader {
public:
    ZlibRuntimeLoader();
    ~ZlibRuntimeLoader();

    bool Load();
    bool Decompress(unsigned char* out, unsigned int* outLen,
                    const unsigned char* in, unsigned int inLen);
    bool Compress(unsigned char* out, unsigned int* outLen,
                  const unsigned char* in, unsigned int inLen);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace Compression
} // namespace RawrXD
