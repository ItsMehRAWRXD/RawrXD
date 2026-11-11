bool Deep2Engine::Initialize(const std::string& modelPath, const std::string& manifestPath, bool forceWholeLoader) {
    if (!manifestPath.empty()) {
        ParseOllamaManifest(manifestPath, &ctx);
    }

    if (forceWholeLoader || !romMode) {
        bool result = LoadUniversalBlob(modelPath, &ctx);
        if (result) { initialized = true; SynchronizeRoPEScaling(); }
        return result;
    }

    // --- ROM (paged) path: header/tensor-directory only, no whole-model allocation ---
    if (!rom.addShard(modelPath)) return false;
    if (!rom.finalizeIndex()) return false;

    // Best-effort Vulkan initialization on all discovered AMD discrete GPUs.
    vulkan = std::make_unique<deep2::VulkanDevice>();
    vulkanReady = vulkan->init();
    if (vulkanReady) {
        fprintf(stderr, "[ROM_EXEC_BRIDGE] Vulkan ready on %zu GPU(s)\n", vulkan->gpuCount());
        for (size_t i = 0; i < vulkan->gpuCount(); ++i) {
            const auto* g = vulkan->gpu(i);
            fprintf(stderr, "[VULKAN] gpu%zu: %s (%llu MB)\n", i, g->name.c_str(),
                    (unsigned long long)(g->vramBytes / (1024ull * 1024ull)));
        }
    } else {
        fprintf(stderr, "[ROM_EXEC_BRIDGE] Vulkan unavailable; CPU-only execution\n");
    }

    initialized = true;
    SynchronizeRoPEScaling();
    return true;
}

void Deep2Engine::Shutdown() {
    if (vulkan) { vulkan->shutdown(); vulkan.reset(); }
    initialized = false;
}