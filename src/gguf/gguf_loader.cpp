// =============================================================================
// RawrXD-CoreRuntime: GGUF Loader Implementation (Stub)
// =============================================================================
// PURPOSE: Headless GGUF model loading without UI dependencies
// =============================================================================

#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include "core_runtime/gguf_loader.h"
#include <cstring>
#include <cstdio>

namespace RawrXD {
namespace Core {

// Stub implementation - real logic in Phase 2
class GGUFLoader::Impl {
public:
    char modelPath[256];
    bool loaded = false;
};

GGUFLoader::GGUFLoader() : pImpl(new Impl()) {}
GGUFLoader::~GGUFLoader() = default;
GGUFLoader::GGUFLoader(GGUFLoader&&) noexcept = default;
GGUFLoader& GGUFLoader::operator=(GGUFLoader&&) noexcept = default;

bool GGUFLoader::Load(const char* path) {
    if (!path || std::strlen(path) == 0) {
        return false;
    }
    
    // Stub: just store the path
    std::snprintf(pImpl->modelPath, sizeof(pImpl->modelPath), "%s", path);
    pImpl->loaded = true;
    
    return true;
}

bool GGUFLoader::IsLoaded() const {
    return pImpl->loaded;
}

const char* GGUFLoader::GetModelPath() const {
    return pImpl->modelPath;
}

void GGUFLoader::Unload() {
    pImpl->loaded = false;
    pImpl->modelPath[0] = '\0';
}

} // namespace Core
} // namespace RawrXD
