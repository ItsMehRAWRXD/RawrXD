// ============================================================================
// dynamic_model_loader.cpp
// Implementation: Hot-swappable model loader with memory-aware backend selection
// ============================================================================

#include "dynamic_model_loader.h"
#include "inference_engine.h"
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

// --- Memory Query ---
size_t DynamicModelLoader::getAvailableVRAMMB() const {
    // Query GPU memory via DXGI or Vulkan
    // Fallback: return configured max minus estimated usage
    return m_max_vram_mb;  // Simplified - integrate with Vulkan/DX12 backend
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
    if (model.supports_gpu && getAvailableVRAMMB() > model.estimated_vram_mb) {
        return true;
    }
    return getAvailableRAMMB() > model.estimated_ram_mb;
}

// --- Model Discovery ---
std::vector<ModelCapability> DynamicModelLoader::scanModelDirectory(const std::string& dir) {
    std::vector<ModelCapability> models;
    if (!std::filesystem::exists(dir)) return models;

    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (entry.is_regular_file()) {
            auto ext = entry.path().extension().string();
            if (ext == ".gguf" || ext == ".bin" || ext == ".safetensors") {
                models.push_back(probeModel(entry.path().string()));
            }
        }
    }
    return models;
}

ModelCapability DynamicModelLoader::probeModel(const std::string& path) {
    ModelCapability cap;
    cap.path = path;
    cap.name = std::filesystem::path(path).stem().string();

    // Get file size
    if (std::filesystem::exists(path)) {
        cap.size_bytes = std::filesystem::file_size(path);
        cap.estimated_ram_mb = static_cast<float>(cap.size_bytes / (1024.0 * 1024.0));
        cap.estimated_vram_mb = cap.estimated_ram_mb * 1.2f;  // GPU overhead
    }

    // Parse GGUF header for metadata if applicable
    if (path.ends_with(".gguf")) {
        std::ifstream file(path, std::ios::binary);
        if (file) {
            uint32_t magic = 0;
            file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
            if (magic == 0x46554747) {  // "GGUF" little-endian
                uint32_t version = 0;
                file.read(reinterpret_cast<char*>(&version), sizeof(version));
                uint64_t tensor_count = 0, kv_count = 0;
                file.read(reinterpret_cast<char*>(&tensor_count), sizeof(tensor_count));
                file.read(reinterpret_cast<char*>(&kv_count), sizeof(kv_count));
                // Could parse KV pairs here for context_length, architecture, etc.
                cap.context_length = 4096;  // Default, override if parsed
            }
        }
    }

    // Heuristic: models under 4GB are "tiny" and good for testing
    if (cap.estimated_ram_mb < 4096) {
        cap.supports_medusa = true;
        cap.supports_speculative = true;
    }

    return cap;
}

// --- Loading ---
LoadResult DynamicModelLoader::loadModel(const std::string& path, LoadBackend backend) {
    std::lock_guard<std::mutex> lock(m_mutex);
    LoadResult result;

    auto start = std::chrono::high_resolution_clock::now();

    // Unload current if any
    if (m_loaded.load()) {
        unloadModel();
    }

    // Probe target model
    auto cap = probeModel(path);
    if (cap.size_bytes == 0) {
        result.error = "Model file not found or empty: " + path;
        return result;
    }

    // Backend selection
    switch (backend) {
        case LoadBackend::Auto:
            if (canFitModel(cap) && cap.supports_gpu) {
                result = tryLoadGPU(path);
            } else if (getAvailableRAMMB() > cap.estimated_ram_mb) {
                result = tryLoadCPU(path);
            } else {
                result = tryLoadSpillover(path);
            }
            break;
        case LoadBackend::GPU:
            result = tryLoadGPU(path);
            break;
        case LoadBackend::CPU:
            result = tryLoadCPU(path);
            break;
        case LoadBackend::Spillover:
            result = tryLoadSpillover(path);
            break;
    }

    auto end = std::chrono::high_resolution_clock::now();
    result.load_time_ms = static_cast<float>(
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()
    );

    if (result.success) {
        m_loaded.store(true);
        m_current_model = path;

        // Wire into inference engine if available
        if (m_engine) {
            if (!m_engine->LoadModel(path)) {
                result.error = "DynamicModelLoader: file ready but inference engine LoadModel() failed";
                result.success = false;
                m_loaded.store(false);
                m_current_model.clear();
                return result;
            }
        }

        if (m_on_load) m_on_load(result);
    }

    return result;
}

LoadResult DynamicModelLoader::loadTinyModel() {
    if (!m_tiny_model.empty() && std::filesystem::exists(m_tiny_model)) {
        return loadModel(m_tiny_model, LoadBackend::Auto);
    }

    // Fallback: scan common directories for small models
    std::vector<std::string> search_paths = {
        "F:\\OllamaModels",
        "D:\\models",
        "C:\\models",
        ".\\models"
    };

    for (const auto& dir : search_paths) {
        auto models = scanModelDirectory(dir);
        for (const auto& model : models) {
            if (model.estimated_ram_mb < 4096) {  // Under 4GB = tiny
                return loadModel(model.path, LoadBackend::Auto);
            }
        }
    }

    LoadResult result;
    result.error = "No tiny model found in search paths";
    return result;
}

bool DynamicModelLoader::unloadModel() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_loaded.load()) return true;

    // Unload from inference engine if available
    if (m_engine) {
        m_engine->ClearCache();
    }

    m_loaded.store(false);
    m_current_model.clear();
    m_speculative_enabled.store(false);

    if (m_on_unload) m_on_unload();
    return true;
}

bool DynamicModelLoader::isModelLoaded() const {
    return m_loaded.load();
}

std::string DynamicModelLoader::currentModelPath() const {
    return m_current_model;
}

// --- Hot Swap ---
LoadResult DynamicModelLoader::swapToModel(const std::string& path, LoadBackend backend) {
    std::string old_model = m_current_model;
    auto result = loadModel(path, backend);
    if (!result.success && !old_model.empty()) {
        // Rollback to previous model on failure
        loadModel(old_model, backend);
    }
    return result;
}

// --- Backend Implementations ---
LoadResult DynamicModelLoader::tryLoadGPU(const std::string& path) {
    LoadResult result;
    // TODO: Integrate with Vulkan/DX12 compute backend
    // For now, mark as success if file exists (actual GPU load deferred)
    if (std::filesystem::exists(path)) {
        result.success = true;
        result.backend_used = "GPU";
        result.vram_used_mb = static_cast<size_t>(
            std::filesystem::file_size(path) / (1024 * 1024)
        );
    } else {
        result.error = "GPU load failed: file not found";
    }
    return result;
}

LoadResult DynamicModelLoader::tryLoadCPU(const std::string& path) {
    LoadResult result;
    if (std::filesystem::exists(path)) {
        result.success = true;
        result.backend_used = "CPU";
        result.ram_used_mb = static_cast<size_t>(
            std::filesystem::file_size(path) / (1024 * 1024)
        );
    } else {
        result.error = "CPU load failed: file not found";
    }
    return result;
}

LoadResult DynamicModelLoader::tryLoadSpillover(const std::string& path) {
    LoadResult result;
    // GPU + CPU spillover: load hot layers to GPU, cold layers to CPU RAM
    // For models exceeding VRAM but fitting in total RAM+VRAM
    auto cap = probeModel(path);
    size_t vram_available = getAvailableVRAMMB();
    size_t ram_available = getAvailableRAMMB();

    if (cap.estimated_vram_mb > vram_available &&
        cap.estimated_ram_mb <= (vram_available + ram_available)) {
        // Attempt GPU load for hot layers first
        result = tryLoadGPU(path);
        if (result.success) {
            result.backend_used = "GPU-Spillover";
            result.ram_used_mb = static_cast<size_t>(cap.estimated_ram_mb) - vram_available;
            result.vram_used_mb = vram_available;
        } else {
            // Fallback to pure CPU
            result = tryLoadCPU(path);
            result.backend_used = "CPU-Fallback";
        }
    } else {
        result.error = "Spillover failed: model exceeds total available memory";
    }
    return result;
}

// --- Speculative Decoding ---
bool DynamicModelLoader::enableMedusa(const std::string& draft_model_path) {
    if (!std::filesystem::exists(draft_model_path)) return false;
    // TODO: Load draft model for Medusa tree attention
    m_speculative_enabled.store(true);
    return true;
}

bool DynamicModelLoader::enableSpeculativeDecoding(int draft_tokens) {
    m_speculative_enabled.store(true);
    return true;
}

void DynamicModelLoader::disableSpeculativeDecoding() {
    m_speculative_enabled.store(false);
}

bool DynamicModelLoader::isSpeculativeEnabled() const {
    return m_speculative_enabled.load();
}

} // namespace RawrXD
