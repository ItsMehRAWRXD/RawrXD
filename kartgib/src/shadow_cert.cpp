#include "vulkan_renderer.hpp"
#include "forensics_png.hpp"
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <windows.h>

static std::vector<uint8_t> shadowOffRGB;

static void storeRGB(std::vector<uint8_t>& dst, const uint8_t* px, uint32_t n, bool bgra) {
    dst.resize(static_cast<size_t>(n) * 3);
    for (uint32_t i = 0; i < n; ++i) {
        const uint8_t* p = px + static_cast<size_t>(i) * 4;
        dst[i * 3] = static_cast<uint8_t>(bgra ? p[2] : p[0]);
        dst[i * 3 + 1] = p[1];
        dst[i * 3 + 2] = static_cast<uint8_t>(bgra ? p[0] : p[2]);
    }
}
static int channel(const uint8_t* px, uint32_t i, int c, bool bgra) {
    const uint8_t* p = px + static_cast<size_t>(i) * 4;
    if (c == 1) return p[1];
    if (c == 0) return bgra ? p[2] : p[0];
    return bgra ? p[0] : p[2];
}

void VulkanRenderer::armShadowCert() {
    shadowCertArmed_ = true;
    shadowCertStep_ = 0;
    shadowCertWarmup_ = 0;
    debugTriangleMode_ = false;
    std::cout << "[G05_SHADOW] armed off,on,cascade" << std::endl;
}

void VulkanRenderer::prepareShadowCert() {
    if (!shadowCertArmed_ || shadowCertStep_ < 0 || shadowCertStep_ > 2) return;
    if (shadowCertWarmup_ < 2) { shadowCertWarmup_++; return; }
    debugTriangleMode_ = false;
    g04SkipAtmosphere_ = false;
    g04SkipGeometry_ = false;
    readbackThisFrame_ = true;
    lightDiag_ = shadowCertStep_ == 2 ? 5.0f : 0.0f;
    shadowsWanted_ = shadowCertStep_ != 0;
    g04Label_ = shadowCertStep_ == 0 ? "shadow_off" : shadowCertStep_ == 1 ? "shadow_on" : "cascade";
}

void VulkanRenderer::noteShadowCert(const uint8_t* pixels, bool bgra) {
    if (!shadowCertArmed_ || shadowCertStep_ < 0 || shadowCertStep_ > 2) return;
    const uint32_t n = g04Width_ * g04Height_;
    wchar_t modulePath[32768] = {};
    GetModuleFileNameW(nullptr, modulePath, 32768);
    auto evidence = std::filesystem::path(modulePath).parent_path().parent_path().parent_path().parent_path() / "evidence";
    std::filesystem::create_directories(evidence);
    const char* pngs[] = {"kartgib_shadow_off.png", "kartgib_shadow_on.png", "kartgib_shadow_cascade.png"};
    writeStoredPng(evidence / pngs[shadowCertStep_], pixels, g04Width_, g04Height_, bgra);
    if (shadowCertStep_ == 0) storeRGB(shadowOffRGB, pixels, n, bgra);
    if (shadowCertStep_ == 1 && shadowOffRGB.size() == static_cast<size_t>(n) * 3) {
        shadowDarkPixels_ = shadowPartialPixels_ = 0;
        for (uint32_t i = 0; i < n; ++i) {
            int drop = 0;
            for (int c = 0; c < 3; ++c) {
                int d = shadowOffRGB[i * 3 + c] - channel(pixels, i, c, bgra);
                if (d > 0) drop += d;
            }
            if (drop > 40) shadowDarkPixels_++;
            else if (drop > 12) shadowPartialPixels_++;
        }
    }
    if (shadowCertStep_ == 2) {
        cascadePixels_[0] = cascadePixels_[1] = cascadePixels_[2] = cascadePixels_[3] = 0;
        for (uint32_t i = 0; i < n; ++i) {
            int r = channel(pixels, i, 0, bgra), g = channel(pixels, i, 1, bgra), b = channel(pixels, i, 2, bgra);
            if (r > 200 && g < 40 && b < 40) cascadePixels_[0]++;
            else if (g > 200 && r < 40 && b < 40) cascadePixels_[1]++;
            else if (b > 200 && r < 40 && g < 40) cascadePixels_[2]++;
            else if (r > 200 && g > 200 && b < 40) cascadePixels_[3]++;
        }
        const bool darkOk = shadowDarkPixels_ > 1000 && shadowPartialPixels_ > 100; int used = 0;
        for (int c = 0; c < 4; ++c) if (cascadePixels_[c] > 500) used++;
        std::ofstream json(evidence / "kartgib_g05_shadows.json");
        json << "{\"gate\":\"KARTGIB_G05_DIRECTIONAL_LIGHTING_AND_SHADOWS_001\",\"dark_pixels\":"
             << shadowDarkPixels_ << ",\"partial_pixels\":" << shadowPartialPixels_
             << ",\"cascade\":[" << cascadePixels_[0] << "," << cascadePixels_[1] << ","
             << cascadePixels_[2] << "," << cascadePixels_[3] << "],\"cascades_used\":" << used
             << ",\"shadow_pixels\":\"" << (darkOk ? "PASS" : "FAIL") << "\",\"cascade_selection\":\""
             << (used >= 3 ? "PASS" : "FAIL") << "\",\"gpu_ms\":" << lastGpuMs_
             << ",\"validation\":\"" << (enableValidation_ ? "MEASURED" : "UNKNOWN")
             << "\",\"validation_messages\":" << validationCount() << "}\n";
        std::cout << "[G05_SHADOW] dark=" << shadowDarkPixels_ << " partial=" << shadowPartialPixels_
                  << " cascades=" << cascadePixels_[0] << "," << cascadePixels_[1] << "," << cascadePixels_[2]
                  << "," << cascadePixels_[3] << " gpu_ms=" << lastGpuMs_ << " validation_messages=" << validationCount() << std::endl;
        shadowCertArmed_ = false;
        shadowCertStep_ = -1; shadowsWanted_ = true;
        return;
    }
    shadowCertStep_++;
}
