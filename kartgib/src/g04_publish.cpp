#include "vulkan_renderer.hpp"
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_set>
#include <vector>
#include <windows.h>

static int encode8(float c, bool srgb) {
    if (srgb) {
        c = c <= 0.0031308f ? 12.92f * c : 1.055f * std::pow(c, 1.0f / 2.4f) - 0.055f;
    }
    int v = static_cast<int>(c * 255.0f + 0.5f);
    if (v < 0) return 0;
    if (v > 255) return 255;
    return v;
}

void VulkanRenderer::publishG04Readback() {
    if (g04Buffer_ == VK_NULL_HANDLE) return;
    void* mapped = nullptr;
    vkMapMemory(device_, g04Memory_, 0, VK_WHOLE_SIZE, 0, &mapped);
    const auto* pixels = static_cast<const uint8_t*>(mapped);
    const bool srgb = swapchainImageFormat_ == VK_FORMAT_R8G8B8A8_SRGB
        || swapchainImageFormat_ == VK_FORMAT_B8G8R8A8_SRGB;
    const bool bgra = swapchainImageFormat_ == VK_FORMAT_B8G8R8A8_UNORM
        || swapchainImageFormat_ == VK_FORMAT_B8G8R8A8_SRGB;
    const int cr = encode8(0.1f, srgb);
    const int cg = encode8(0.1f, srgb);
    const int cb = encode8(0.15f, srgb);
    uint64_t nonClear = 0;
    uint64_t magenta = 0;
    std::unordered_set<uint32_t> colors;
    const uint32_t stride = (g04Width_ * 3u + 3u) & ~3u;
    std::vector<uint8_t> bmp(stride * g04Height_);
    for (uint32_t y = 0; y < g04Height_; ++y) {
        for (uint32_t x = 0; x < g04Width_; ++x) {
            const uint8_t* p = pixels + (static_cast<uint64_t>(y) * g04Width_ + x) * 4;
            int r = bgra ? p[2] : p[0];
            int g = p[1];
            int b = bgra ? p[0] : p[2];
            if (std::abs(r - cr) > 2 || std::abs(g - cg) > 2 || std::abs(b - cb) > 2) nonClear++;
            if (r >= 250 && g <= 8 && b >= 250) magenta++;
            if (forensicsArmed_) {
                colors.insert((static_cast<uint32_t>(r) << 16) | (static_cast<uint32_t>(g) << 8) | static_cast<uint32_t>(b));
            }
            uint32_t dy = g04Height_ - 1 - y;
            uint8_t* dst = bmp.data() + dy * stride + x * 3;
            dst[0] = static_cast<uint8_t>(b);
            dst[1] = static_cast<uint8_t>(g);
            dst[2] = static_cast<uint8_t>(r);
        }
    }
    noteForensicsReadback(nonClear, colors.size(), pixels, bgra);
    noteShadowCert(pixels, bgra);
    noteChunkTour(pixels, bgra);
    noteOceanTour(pixels, bgra);
    noteProductTour(pixels, bgra);
    noteEditorShot(pixels, bgra);
    vkUnmapMemory(device_, g04Memory_);
    wchar_t modulePath[32768] = {};
    DWORD length = GetModuleFileNameW(nullptr, modulePath, 32768);
    std::filesystem::path dir = std::filesystem::path(std::wstring(modulePath, length)).parent_path();
    std::string stem = std::string("g04_") + g04Label_;
    std::ofstream image(dir / (stem + ".bmp"), std::ios::binary);
    uint32_t fileSize = 54u + static_cast<uint32_t>(bmp.size());
    uint32_t pixelOffset = 54;
    uint32_t headerSize = 40;
    int32_t width = static_cast<int32_t>(g04Width_);
    int32_t height = static_cast<int32_t>(g04Height_);
    uint16_t planes = 1;
    uint16_t bits = 24;
    uint32_t zero = 0;
    image.write("BM", 2);
    image.write(reinterpret_cast<char*>(&fileSize), 4);
    image.write(reinterpret_cast<char*>(&zero), 4);
    image.write(reinterpret_cast<char*>(&pixelOffset), 4);
    image.write(reinterpret_cast<char*>(&headerSize), 4);
    image.write(reinterpret_cast<char*>(&width), 4);
    image.write(reinterpret_cast<char*>(&height), 4);
    image.write(reinterpret_cast<char*>(&planes), 2);
    image.write(reinterpret_cast<char*>(&bits), 2);
    image.write(reinterpret_cast<char*>(&zero), 4);
    image.write(reinterpret_cast<char*>(&zero), 4);
    image.write(reinterpret_cast<char*>(&zero), 4);
    image.write(reinterpret_cast<char*>(&zero), 4);
    image.write(reinterpret_cast<char*>(&zero), 4);
    image.write(reinterpret_cast<char*>(&zero), 4);
    image.write(reinterpret_cast<const char*>(bmp.data()), static_cast<std::streamsize>(bmp.size()));
    std::cout << "[G04] Readback " << g04Width_ << "x" << g04Height_
              << " format=" << static_cast<int>(swapchainImageFormat_)
              << " clear=" << cr << "," << cg << "," << cb
              << " nonClear=" << nonClear << " magenta=" << magenta
              << " tolerance=2 label=" << g04Label_ << std::endl;
    std::ofstream receipt(dir / (stem + ".txt"));
    receipt << "label=" << g04Label_ << "\nwidth=" << g04Width_ << "\nheight=" << g04Height_
            << "\nformat=" << static_cast<int>(swapchainImageFormat_)
            << "\nnonClear=" << nonClear << "\nmagenta=" << magenta
            << "\ntolerance=2\nclear=" << cr << "," << cg << "," << cb << "\n";
    vkDestroyBuffer(device_, g04Buffer_, nullptr);
    vkFreeMemory(device_, g04Memory_, nullptr);
    g04Buffer_ = VK_NULL_HANDLE;
    g04Memory_ = VK_NULL_HANDLE;
}
