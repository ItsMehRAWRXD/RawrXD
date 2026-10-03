#pragma once
#include <cstdint>
#include <string>

namespace rawrxd { namespace gguf {

struct NativeGGUFLoaderConfig {
    uint32_t flags = 0;
    bool verifyChecksum = true;
};

bool NativeLoadGGUF(const std::string& path, const NativeGGUFLoaderConfig& config);

}} // namespace rawrxd::gguf
