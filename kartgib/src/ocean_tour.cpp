#include "ocean_field.hpp"
#include "vulkan_renderer.hpp"
#include "forensics_png.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <windows.h>
#include <psapi.h>

static int countIf(const uint8_t* pixels, int n, bool bgra, bool water) {
    int count = 0;
    for (int i = 0; i < n; ++i) {
        const uint8_t* p = pixels + i * 4;
        int b = bgra ? p[0] : p[2], g = p[1], r = bgra ? p[2] : p[0];
        if (water ? (b > r + 12 && b > 35) : (g > r + 8 && g > 35 && b + 10 < g)) ++count;
    }
    return count;
}

void VulkanRenderer::armOceanTour() {
    oceanTourArmed_ = true; oceanTourStep_ = 0; oceanTourWarmup_ = 0; oceanSimTime_ = 0.0f;
    debugTriangleMode_ = false;
    std::cout << "[OCEAN] tour t=0 then t=3" << std::endl;
}
void VulkanRenderer::prepareOceanTour() {
    if (!oceanTourArmed_ || oceanTourStep_ < 0 || oceanTourStep_ > 1) return;
    if (oceanTourWarmup_ < 2) { ++oceanTourWarmup_; oceanSimTime_ = 0.0f; return; }
    debugTriangleMode_ = false; g04SkipAtmosphere_ = false; g04SkipGeometry_ = false; readbackThisFrame_ = true;
    oceanSimTime_ = oceanTourStep_ == 0 ? 0.0f : 3.0f;
    g04Label_ = oceanTourStep_ == 0 ? "ocean_t0" : "ocean_t1";
}
void VulkanRenderer::noteOceanTour(const uint8_t* pixels, bool bgra) {
    if (!oceanTourArmed_ || oceanTourStep_ < 0 || oceanTourStep_ > 1) return;
    static int water0 = 0, land0 = 0;
    int water = countIf(pixels, g04Width_ * g04Height_, bgra, true);
    int land = countIf(pixels, g04Width_ * g04Height_, bgra, false);
    wchar_t modulePath[32768] = {};
    GetModuleFileNameW(nullptr, modulePath, 32768);
    auto evidence = std::filesystem::path(modulePath).parent_path().parent_path().parent_path().parent_path() / "evidence";
    std::filesystem::create_directories(evidence);
    writeStoredPng(evidence / (oceanTourStep_ == 0 ? "kartgib_ocean_t0.png" : "kartgib_ocean_t1.png"), pixels, g04Width_, g04Height_, bgra);
    if (oceanTourStep_ == 0) { water0 = water; land0 = land; oceanTourStep_ = 1; oceanSimTime_ = 3.0f; return; }
    const OceanCert& cert = oceanCpuCert();
    PROCESS_MEMORY_COUNTERS mem{};
    GetProcessMemoryInfo(GetCurrentProcess(), &mem, sizeof(mem));
    std::ofstream json(evidence / "G06_FFT_OCEAN_CERTIFICATION_001.json");
    json << "{\"gate\":\"G06_FFT_OCEAN_CERTIFICATION_001\",\"fft\":\"" << (cert.fft ? "PASS" : "FAIL")
         << "\",\"spectra\":\"" << (cert.spectra ? "PASS" : "FAIL") << "\",\"hermitian\":\"" << (cert.hermitian ? "PASS" : "FAIL")
         << "\",\"animated\":\"" << (cert.animated ? "PASS" : "FAIL") << "\",\"foam\":\"" << (cert.foam ? "PARTIAL" : "FAIL")
         << "\",\"buoyancy\":\"" << (cert.buoyant ? "PASS" : "FAIL") << "\",\"cascades\":\"" << (cert.cascade ? "PASS" : "FAIL")
         << "\",\"gpu_fft\":\"" << cert.gpu << "\",\"gpu_error\":" << cert.gpuError << ",\"height\":[" << cert.minH << "," << cert.maxH
         << "],\"water_pixels\":[" << water0 << "," << water << "],\"land_pixels\":[" << land0 << "," << land
         << "],\"gpu_ms\":" << lastGpuMs_ << ",\"working_set\":" << mem.WorkingSetSize
         << ",\"validation\":\"" << (!enableValidation_ ? "UNKNOWN" : (validationCount() == 0 ? "PASS" : "FAIL"))
         << "\",\"validation_messages\":" << validationCount()
         << ",\"frames\":[\"evidence/kartgib_ocean_t0.png\",\"evidence/kartgib_ocean_t1.png\"]}\n";
    std::cout << "[OCEAN] water=" << water0 << "," << water << " land=" << land0 << "," << land << std::endl;
    oceanTourArmed_ = false; oceanTourStep_ = -1;
}
