// ============================================================================
// dynamic_model_loader.cpp — Resolve + OpenSession only (Batch 004).
// No independent decode/runtime authority; ProductRun owns generation.
// ============================================================================

#include "dynamic_model_loader.h"
#include "product/gateway/product_deep2_infer.hpp"
#include <windows.h>
#include <psapi.h>
#include <chrono>
#include <fstream>
#include <filesystem>

#pragma comment(lib, "psapi.lib")

namespace RawrXD {

DynamicModelLoader& DynamicModelLoader::instance() {
    static DynamicModelLoader inst;
    return inst;
}

size_t DynamicModelLoader::getAvailableVRAMMB() const {
    return m_max_vram_mb;
}

size_t DynamicModelLoader::getAvailableRAMMB() const {
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        return static_cast<size_t>(memStatus.ullAvailPhys / (1024 * 1024));
    }
    return m_max_ram_mb;
}

bool DynamicModelLoader::canFitModel(const ModelCapability& model) const {
    if (model.supports_gpu && getAvailableVRAMMB() > model.estimated_vram_mb)
        return true;
    return getAvailableRAMMB() > model.estimated_ram_mb;
}

std::vector<ModelCapability> DynamicModelLoader::scanModelDirectory(const std::string& dir) {
    std::vector<ModelCapability> models;
    if (!std::filesystem::exists(dir)) return models;
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (entry.is_regular_file()) {
            auto ext = entry.path().extension().string();
            if (ext == ".gguf" || ext == ".bin" || ext == ".safetensors")
                models.push_back(probeModel(entry.path().string()));
        }
    }
    return models;
}

ModelCapability DynamicModelLoader::probeModel(const std::string& path) {
    ModelCapability cap;
    cap.path = path;
    cap.name = std::filesystem::path(path).stem().string();
    if (std::filesystem::exists(path)) {
        cap.size_bytes = std::filesystem::file_size(path);
        cap.estimated_ram_mb = static_cast<float>(cap.size_bytes / (1024.0 * 1024.0));
        cap.estimated_vram_mb = cap.estimated_ram_mb * 1.2f;
    }
    return cap;
}

LoadResult DynamicModelLoader::loadModel(const std::string& path, LoadBackend /*backend*/) {
    std::lock_guard<std::mutex> lock(m_mutex);
    LoadResult result;
    auto start = std::chrono::high_resolution_clock::now();
    if (m_loaded.load()) {
        rawr::ProductCloseSession();
        m_loaded.store(false);
        m_current_model.clear();
    }
    auto cap = probeModel(path);
    if (cap.size_bytes == 0) {
        result.error = "Model file not found or empty: " + path;
        return result;
    }
#ifdef _WIN32
    _putenv_s("RAWRXD_PRODUCT_MODEL", path.c_str());
#endif
    if (!rawr::ProductOpenSession(path.c_str())) {
        result.error = "ProductOpenSession failed (Resolve+OpenSession)";
        result.success = false;
        return result;
    }
    result.success = true;
    result.backend_used = "ProductOpenSession";
    result.ram_used_mb = static_cast<size_t>(cap.estimated_ram_mb);
    m_loaded.store(true);
    m_current_model = path;
    auto end = std::chrono::high_resolution_clock::now();
    result.load_time_ms = static_cast<float>(
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());
    if (m_on_load) m_on_load(result);
    return result;
}

LoadResult DynamicModelLoader::loadTinyModel() {
    if (!m_tiny_model.empty() && std::filesystem::exists(m_tiny_model))
        return loadModel(m_tiny_model, LoadBackend::Auto);
    for (const auto& dir : {"F:\\OllamaModels", "D:\\models", "C:\\models", ".\\models"}) {
        auto models = scanModelDirectory(dir);
        for (const auto& model : models) {
            if (model.estimated_ram_mb < 4096)
                return loadModel(model.path, LoadBackend::Auto);
        }
    }
    LoadResult result;
    result.error = "No tiny model found — UNAVAILABLE";
    return result;
}

bool DynamicModelLoader::unloadModel() {
    std::lock_guard<std::mutex> lock(m_mutex);
    rawr::ProductCloseSession();
    m_loaded.store(false);
    m_current_model.clear();
    m_speculative_enabled.store(false);
    if (m_on_unload) m_on_unload();
    return true;
}

bool DynamicModelLoader::isModelLoaded() const {
    return m_loaded.load() && rawr::ProductSessionOpen();
}

std::string DynamicModelLoader::currentModelPath() const {
    return m_current_model;
}

LoadResult DynamicModelLoader::swapToModel(const std::string& path, LoadBackend backend) {
    std::string old_model = m_current_model;
    auto result = loadModel(path, backend);
    if (!result.success && !old_model.empty())
        loadModel(old_model, backend);
    return result;
}

LoadResult DynamicModelLoader::tryLoadGPU(const std::string& path) {
    /* No alt GPU decode authority — session open only. */
    return loadModel(path, LoadBackend::Auto);
}

LoadResult DynamicModelLoader::tryLoadCPU(const std::string& path) {
    return loadModel(path, LoadBackend::Auto);
}

LoadResult DynamicModelLoader::tryLoadSpillover(const std::string& path) {
    return loadModel(path, LoadBackend::Auto);
}

bool DynamicModelLoader::enableMedusa(const std::string&) {
    return false; /* UNAVAILABLE — not product path */
}

bool DynamicModelLoader::enableSpeculativeDecoding(int) {
    return false; /* UNAVAILABLE — no false success */
}

void DynamicModelLoader::disableSpeculativeDecoding() {
    m_speculative_enabled.store(false);
}

bool DynamicModelLoader::isSpeculativeEnabled() const {
    return false;
}

} // namespace RawrXD
