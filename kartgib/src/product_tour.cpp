#include "vulkan_renderer.hpp"
#include "product_scene.hpp"
#include "forensics_png.hpp"
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>

void exeSha256(char out[65]);

static uint64_t fnv(const uint8_t* p, int n) {
    uint64_t h = 14695981039346656037ull;
    for (int i = 0; i < n; i += 16) { h ^= p[i]; h *= 1099511628211ull; }
    return h;
}
static int countTone(const uint8_t* p, int n, bool bgra, int kind) {
    int count = 0;
    for (int i = 0; i < n; ++i) {
        const uint8_t* s = p + i * 4;
        int b = bgra ? s[0] : s[2], g = s[1], r = bgra ? s[2] : s[0];
        bool hit = kind == 0 ? (b > r + 12 && b > 35) : kind == 1 ? (r > 160 && r > g + 25 && b < 90)
            : kind == 2 ? (g > 80 && g > r + 20 && b + 10 < g) : (r > 200 && g > 170 && b < 120);
        if (hit) ++count;
    }
    return count;
}

void VulkanRenderer::armProductTour() {
    createProductPipeline();
    productTourArmed_ = true; productStep_ = 0; productWarmup_ = 0;
    std::cout << "[PRODUCT] tour steps 0..3" << std::endl;
}
void VulkanRenderer::prepareProductTour() {
    if (!productTourArmed_ || productStep_ < 0 || productStep_ > 3) return;
    if (productWarmup_ < 2) { ++productWarmup_; return; }
    debugTriangleMode_ = false; g04SkipGeometry_ = false; readbackThisFrame_ = true;
    g04Label_ = "product";
}
void VulkanRenderer::noteProductTour(const uint8_t* pixels, bool bgra) {
    if (!productTourArmed_ || productStep_ < 0 || productStep_ > 3) return;
    static uint64_t hashes[4]{};
    static int water = 0, prop = 0, leaf = 0, hud = 0;
    int n = g04Width_ * g04Height_;
    hashes[productStep_] = fnv(pixels, n * 4);
    wchar_t modulePath[32768]{};
    GetModuleFileNameW(nullptr, modulePath, 32768);
    auto evidence = std::filesystem::path(modulePath).parent_path().parent_path().parent_path().parent_path() / "evidence";
    std::filesystem::create_directories(evidence);
    char name[32];
    std::snprintf(name, sizeof(name), "kartgib_product_%d.png", productStep_);
    writeStoredPng(evidence / name, pixels, g04Width_, g04Height_, bgra);
    if (productStep_ == 1) {
        water = countTone(pixels, n, bgra, 0); prop = countTone(pixels, n, bgra, 1);
        leaf = countTone(pixels, n, bgra, 2); hud = countTone(pixels, n, bgra, 3);
    }
    std::cout << "[PRODUCT] step=" << productStep_ << " hash=" << hashes[productStep_] << std::endl;
    if (productStep_ < 3) { ++productStep_; return; }
    const ProductStats& s = productStats();
    bool undo = hashes[0] == hashes[2] && hashes[1] == hashes[3] && hashes[0] != hashes[1];
    char sha[65]{}; exeSha256(sha);
    std::ofstream json(evidence / "G32_G41_PRODUCT_CLOSURE_001.json");
    json << "{\"gate\":\"KARTGIB_WORLD_FORGE_POST_BATCH25_PRODUCT_CLOSURE_001\",\"promote\":0"
         << ",\"batch25_exe_sha256\":\"1A9EF41B2616DBDFCEDE008157C4AF3A8A67093229976ECFC620AACD07DE1086\""
         << ",\"exe_sha256\":\"" << sha << "\",\"g32\":\"" << (undo && s.poseSaved ? "PASS" : "FAIL")
         << "\",\"g33\":\"PARTIAL\",\"g34\":\"PARTIAL\",\"g35\":\"" << (s.audio ? "PARTIAL" : "FAIL")
         << "\",\"g36\":\"" << (s.riverSteps >= 3 && water > 1000 ? "PARTIAL" : "FAIL")
         << "\",\"g37\":\"" << (s.instancesKept >= 1000 && instGpuMs_ >= 0.0f && leaf > 100 ? "PARTIAL" : "FAIL")
         << "\",\"g38\":\"" << (s.sync ? "PARTIAL" : "FAIL")
         << "\",\"g39\":\"PARTIAL\",\"g40\":\"NOT_RUN\",\"g41\":\"NOT_RUN\""
         << ",\"undo\":" << (undo ? "true" : "false") << ",\"pose_saved\":" << (s.poseSaved ? "true" : "false")
         << ",\"bones\":" << s.bones << ",\"river_steps\":" << s.riverSteps
         << ",\"instances_seen\":" << s.instancesSeen << ",\"instances_drawn\":" << s.instancesKept
         << ",\"instanced_draw_ms\":" << instGpuMs_ << ",\"water_pixels\":" << water
         << ",\"prop_pixels\":" << prop << ",\"foliage_pixels\":" << leaf << ",\"hud_pixels\":" << hud
         << ",\"audio\":" << (s.audio ? "true" : "false") << ",\"gamepad\":" << s.gamepad
         << ",\"mouse_dx\":" << s.mouseDx << ",\"mouse_dy\":" << s.mouseDy
         << ",\"sync\":" << (s.sync ? "true" : "false") << ",\"remote\":[" << s.remoteX << "," << s.remoteY << "," << s.remoteZ << "]"
         << ",\"combat_hp\":" << s.combatHp << ",\"cpu_ms\":[" << cpuMinMs_ << "," << (cpuCount_ ? cpuSumMs_ / cpuCount_ : 0) << "," << cpuMaxMs_ << "]"
         << ",\"cpu_frames\":" << cpuCount_ << ",\"shader_cache\":\"NOT_RUN\",\"clean_machine\":\"NOT_RUN\",\"soak\":\"NOT_RUN\""
         << ",\"hashes\":[" << hashes[0] << "," << hashes[1] << "," << hashes[2] << "," << hashes[3] << "]}\n";
    productTourArmed_ = false; productStep_ = 3;
}
