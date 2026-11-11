#include "vulkan_renderer.hpp"
#include "forensics_png.hpp"
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <windows.h>
static std::vector<uint8_t> skyRGB, terrainRGB, diffuseRGB, unlitRGB;
static int encode8(float c, bool srgb) {
    if (srgb) c = c <= 0.0031308f ? 12.92f * c : 1.055f * std::pow(c, 1.0f / 2.4f) - 0.055f;
    int v = static_cast<int>(c * 255.0f + 0.5f);
    return v < 0 ? 0 : v > 255 ? 255 : v;
}
static void storeRGB(std::vector<uint8_t>& dst, const uint8_t* px, uint32_t n, bool bgra) {
    dst.resize(static_cast<size_t>(n) * 3);
    for (uint32_t i = 0; i < n; ++i) {
        const uint8_t* p = px + static_cast<size_t>(i) * 4;
        dst[i * 3] = static_cast<uint8_t>(bgra ? p[2] : p[0]);
        dst[i * 3 + 1] = p[1];
        dst[i * 3 + 2] = static_cast<uint8_t>(bgra ? p[0] : p[2]);
    }
}
static bool nearAt(const uint8_t* a, const uint8_t* b, uint32_t i, int tol) {
    for (int c = 0; c < 3; ++c)
        if (std::abs(int(a[i * 3 + c]) - int(b[i * 3 + c])) > tol) return false;
    return true;
}
static bool nearClear(const uint8_t* a, uint32_t i, const uint8_t clear[3], int tol) {
    for (int c = 0; c < 3; ++c)
        if (std::abs(int(a[i * 3 + c]) - int(clear[c])) > tol) return false;
    return true;
}
void VulkanRenderer::configureForensicsPass() {
    debugTriangleMode_ = false;
    g04SkipAtmosphere_ = forensicsStep_ >= 1 && forensicsStep_ <= 3;
    g04SkipGeometry_ = forensicsStep_ == 0;
    lightDiag_ = forensicsStep_ == 2 ? 1.0f : forensicsStep_ == 3 ? 3.0f : 0.0f;
    readbackThisFrame_ = true;
    const char* labels[] = {"sky", "terrain", "diffuse", "unlit", "combined"};
    g04Label_ = labels[forensicsStep_];
}
void VulkanRenderer::retainForensicsFrame(const uint8_t* pixels, bool bgra) {
    const uint32_t n = g04Width_ * g04Height_;
    if (forensicsStep_ == 0) storeRGB(skyRGB, pixels, n, bgra);
    if (forensicsStep_ == 1) storeRGB(terrainRGB, pixels, n, bgra);
    if (forensicsStep_ == 2) storeRGB(diffuseRGB, pixels, n, bgra);
    if (forensicsStep_ == 3) storeRGB(unlitRGB, pixels, n, bgra);
}
void VulkanRenderer::publishG05Evidence(const uint8_t* pixels, bool bgra) {
    const uint32_t n = g04Width_ * g04Height_;
    std::vector<uint8_t> combined;
    storeRGB(combined, pixels, n, bgra);
    const bool srgb = swapchainImageFormat_ == VK_FORMAT_R8G8B8A8_SRGB || swapchainImageFormat_ == VK_FORMAT_B8G8R8A8_SRGB;
    const uint8_t clear[3] = {static_cast<uint8_t>(encode8(0.1f, srgb)),
        static_cast<uint8_t>(encode8(0.1f, srgb)), static_cast<uint8_t>(encode8(0.15f, srgb))};
    std::vector<uint8_t> mask(static_cast<size_t>(n) * 4, 255);
    skyInFinal_ = terrainInFinal_ = diffusePixels_ = specPixels_ = 0;
    const bool have = skyRGB.size() == n * 3 && terrainRGB.size() == n * 3
        && diffuseRGB.size() == n * 3 && unlitRGB.size() == n * 3;
    if (have) {
        for (uint32_t i = 0; i < n; ++i) {
            const bool drew = !nearClear(terrainRGB.data(), i, clear, 2);
            if (drew && nearAt(combined.data(), terrainRGB.data(), i, 3)) {
                terrainInFinal_++;
                mask[i * 4] = 255;
            } else mask[i * 4] = 0;
            if (!drew && nearAt(combined.data(), skyRGB.data(), i, 3)) {
                skyInFinal_++;
                mask[i * 4 + 1] = 255;
            } else mask[i * 4 + 1] = 0;
            mask[i * 4 + 2] = 0;
            if (drew && !nearAt(terrainRGB.data(), diffuseRGB.data(), i, 8)) specPixels_++;
            if (drew && !nearAt(diffuseRGB.data(), unlitRGB.data(), i, 8)) diffusePixels_++;
        }
    }
    const bool horizon = have && skyInFinal_ > n / 10 && terrainInFinal_ > n / 10;
    const bool diffuseOk = have && diffusePixels_ > 1000;
    const bool specOk = have && specPixels_ > 1000;
    wchar_t modulePath[32768] = {};
    GetModuleFileNameW(nullptr, modulePath, 32768);
    auto evidence = std::filesystem::path(modulePath).parent_path().parent_path().parent_path().parent_path() / "evidence";
    std::filesystem::create_directories(evidence);
    writeStoredPng(evidence / "kartgib_g05_frame.png", pixels, g04Width_, g04Height_, bgra);
    writeStoredPng(evidence / "kartgib_g05_mask.png", mask.data(), g04Width_, g04Height_, false);
    std::ofstream json(evidence / "kartgib_g05_horizon.json");
    json << "{\"gate\":\"KARTGIB_G05_HORIZON\",\"device\":\"" << deviceName_
         << "\",\"sky_in_final\":" << skyInFinal_ << ",\"terrain_in_final\":" << terrainInFinal_
         << ",\"diffuse_pixels\":" << diffusePixels_ << ",\"ggx_pixels\":" << specPixels_
         << ",\"horizon\":\"" << (horizon ? "PASS" : "FAIL")
         << "\",\"diffuse\":\"" << (diffuseOk ? "PASS" : "FAIL")
         << "\",\"ggx_specular\":\"" << (specOk ? "PASS" : "FAIL")
         << "\",\"shadows\":\"NOT_IMPLEMENTED\",\"time_frozen\":0}\n";
    std::cout << "[G05] sky_in_final=" << skyInFinal_ << " terrain_in_final=" << terrainInFinal_
              << " diffuse_pixels=" << diffusePixels_ << " ggx_pixels=" << specPixels_
              << " horizon=" << (horizon ? "PASS" : "FAIL") << " diffuse=" << (diffuseOk ? "PASS" : "FAIL")
              << " ggx=" << (specOk ? "PASS" : "FAIL") << std::endl;
}
