// =============================================================================
// RawrXD-CoreRuntime Public API: GGUF Loader
// =============================================================================
// PURPOSE: Headless GGUF model loading without UI dependencies
// =============================================================================

#ifndef RAWRXD_CORE_GGUF_LOADER_H
#define RAWRXD_CORE_GGUF_LOADER_H

#include "core_export.h"
#include <memory>

namespace RawrXD {
namespace Core {

class RAWRXD_CORE_EXPORT GGUFLoader {
public:
    GGUFLoader();
    ~GGUFLoader();

    // Non-copyable
    GGUFLoader(const GGUFLoader&) = delete;
    GGUFLoader& operator=(const GGUFLoader&) = delete;

    // Movable
    GGUFLoader(GGUFLoader&&) noexcept;
    GGUFLoader& operator=(GGUFLoader&&) noexcept;

    // Load model from GGUF file
    bool Load(const char* path);

    // Check if model is loaded
    bool IsLoaded() const;

    // Get loaded model path
    const char* GetModelPath() const;

    // Unload model
    void Unload();

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace Core
} // namespace RawrXD

#endif // RAWRXD_CORE_GGUF_LOADER_H
