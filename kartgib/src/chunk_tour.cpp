#include "vulkan_renderer.hpp"
#include "forensics_png.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <windows.h>
#include <psapi.h>

static int terrainLike(const uint8_t* pixels, int count, bool bgra) {
    int terrain = 0;
    for (int i = 0; i < count; ++i) {
        const uint8_t* p = pixels + i * 4;
        int b = bgra ? p[0] : p[2];
        int g = p[1];
        int r = bgra ? p[2] : p[0];
        if (r > b + 8 && r > 40 && g > 25) ++terrain;
    }
    return terrain;
}

void VulkanRenderer::armChunkTour() {
    chunkTourArmed_ = true;
    chunkTourStep_ = 0;
    chunkTourWarmup_ = 0;
    chunkFocusX_ = 400.0f;
    debugTriangleMode_ = false;
    std::cout << "[CHUNK] tour x=400 then x=2200" << std::endl;
}

void VulkanRenderer::prepareChunkTour() {
    if (!chunkTourArmed_ || chunkTourStep_ < 0 || chunkTourStep_ > 1) return;
    if (chunkTourWarmup_ < 2) { chunkTourWarmup_++; chunkFocusX_ = 400.0f; return; }
    debugTriangleMode_ = false;
    g04SkipAtmosphere_ = false;
    g04SkipGeometry_ = false;
    readbackThisFrame_ = true;
    chunkFocusX_ = chunkTourStep_ == 0 ? 400.0f : 2200.0f;
    g04Label_ = chunkTourStep_ == 0 ? "chunk_near" : "chunk_far";
}

void VulkanRenderer::noteChunkTour(const uint8_t* pixels, bool bgra) {
    if (!chunkTourArmed_ || chunkTourStep_ < 0 || chunkTourStep_ > 1) return;
    static int nearTerrain = 0;
    int covered = terrainLike(pixels, g04Width_ * g04Height_, bgra);
    wchar_t modulePath[32768] = {};
    GetModuleFileNameW(nullptr, modulePath, 32768);
    auto evidence = std::filesystem::path(modulePath).parent_path().parent_path().parent_path().parent_path() / "evidence";
    std::filesystem::create_directories(evidence);
    const char* name = chunkTourStep_ == 0 ? "kartgib_chunk_near.png" : "kartgib_chunk_far.png";
    writeStoredPng(evidence / name, pixels, g04Width_, g04Height_, bgra);
    if (chunkTourStep_ == 0) { nearTerrain = covered; chunkTourStep_ = 1; chunkFocusX_ = 2200.0f; return; }
    PROCESS_MEMORY_COUNTERS mem{};
    GetProcessMemoryInfo(GetCurrentProcess(), &mem, sizeof(mem));
    std::ofstream json(evidence / "kartgib_world_streaming.json");
    json << "{\"gate\":\"WORLD_CHUNK_STREAMING_001\",\"frames\":[\"evidence/kartgib_chunk_near.png\","
         << "\"evidence/kartgib_chunk_far.png\"],\"camera_x\":[400,2200],\"terrain_like\":["
         << nearTerrain << "," << covered << "],\"gpu_ms\":" << lastGpuMs_
         << ",\"working_set\":" << mem.WorkingSetSize
         << ",\"lod\":\"DISTANCE_STEP\",\"streaming\":\"WINDOW_REBUILD\",\"biome_tint\":\"PAD_A\"}\n";
    std::cout << "[CHUNK] terrain_like near=" << nearTerrain << " far=" << covered
              << " gpu_ms=" << lastGpuMs_ << std::endl;
    chunkTourArmed_ = false;
    chunkTourStep_ = -1;
}
