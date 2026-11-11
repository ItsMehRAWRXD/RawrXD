// =============================================================================
// RawrXD-CoreRuntime: GGUF Loader Implementation (REAL)
// =============================================================================
// PURPOSE: Production GGUF model loading using StreamingGGUFLoader backend
// =============================================================================

#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include "core_runtime/gguf_loader.h"
#include "../streaming_gguf_loader.h"
#include <cstring>
#include <cstdio>
#include <memory>

namespace RawrXD {
namespace Core {

// Real implementation using StreamingGGUFLoader
class GGUFLoader::Impl {
public:
    std::unique_ptr<StreamingGGUFLoader> loader;
    char modelPath[512];
    bool loaded = false;
    
    Impl() : loader(std::make_unique<StreamingGGUFLoader>()) {
        modelPath[0] = '\0';
    }
};

GGUFLoader::GGUFLoader() : pImpl(new Impl()) {}
GGUFLoader::~GGUFLoader() = default;
GGUFLoader::GGUFLoader(GGUFLoader&&) noexcept = default;
GGUFLoader& GGUFLoader::operator=(GGUFLoader&&) noexcept = default;

bool GGUFLoader::Load(const char* path) {
    if (!path || std::strlen(path) == 0) {
        return false;
    }
    
    // Use the streaming loader for real GGUF loading
    if (!pImpl->loader->Open(path)) {
        return false;
    }
    
    // Store the path
    std::snprintf(pImpl->modelPath, sizeof(pImpl->modelPath), "%s", path);
    pImpl->loaded = true;
    
    return true;
}

bool GGUFLoader::IsLoaded() const {
    return pImpl->loaded && pImpl->loader->GetHeader().magic != 0;
}

const char* GGUFLoader::GetModelPath() const {
    return pImpl->modelPath;
}

void GGUFLoader::Unload() {
    pImpl->loader->Close();
    pImpl->loaded = false;
    pImpl->modelPath[0] = '\0';
}

// Additional methods for accessing loaded model data
size_t GGUFLoader::GetTensorCount() const {
    if (!IsLoaded()) return 0;
    return pImpl->loader->GetTensorInfo().size();
}

uint32_t GGUFLoader::GetLayerCount() const {
    if (!IsLoaded()) return 0;
    return pImpl->loader->GetMetadata().layer_count;
}

uint32_t GGUFLoader::GetVocabSize() const {
    if (!IsLoaded()) return 0;
    return pImpl->loader->GetMetadata().vocab_size;
}

uint32_t GGUFLoader::GetEmbeddingDim() const {
    if (!IsLoaded()) return 0;
    return pImpl->loader->GetMetadata().embedding_dim;
}

const char* GGUFLoader::GetArchitecture() const {
    if (!IsLoaded()) return "unknown";
    return pImpl->loader->GetMetadata().architecture.c_str();
}

} // namespace Core
} // namespace RawrXD
