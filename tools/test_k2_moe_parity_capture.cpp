// Standalone source-level smoke test for K2MoEParityCapture.hpp.
// Compile without Deep2 or Vulkan: cl /std:c++17 /EHsc /I src\\deep2 tools\\test_k2_moe_parity_capture.cpp
#ifdef _MSC_VER
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#endif
#include "K2MoEParityCapture.hpp"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <cstdlib>
#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

static void SetCaptureDir(const std::string& v) {
#ifdef _WIN32
    _putenv_s("DEEP2_MOE_PARITY_CAPTURE_DIR", v.c_str());
#else
    setenv("DEEP2_MOE_PARITY_CAPTURE_DIR", v.c_str(), 1);
#endif
}

int main() {
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto dir = std::filesystem::temp_directory_path() /
                     ("rawrxd_k2_parity_test_" + std::to_string(nonce));
    if (!std::filesystem::create_directory(dir)) return 1;
    int code = 0;
    try {
        std::vector<unsigned char> weights(210, 0);
        std::vector<float> activation(256, 1.f);
        float cpu[1] = {2.f};
        float gpu[1] = {2.f};
        SetCaptureDir(dir.string());
        using Deep2::k2_parity_capture::Capture;
        if (!Capture(0, 1, 44, 14, weights.data(), weights.size(),
                     activation.data(), activation.size(), cpu, gpu, 1))
            code = 2;
        if (Capture(0, 1, 44, 14, weights.data(), weights.size(),
                    activation.data(), activation.size(), cpu, gpu, 1))
            code = 3; // refuse overwrite
        if (Capture(0, 1, 45, 12, weights.data(), weights.size(),
                    activation.data(), activation.size(), cpu, gpu, 1))
            code = 4; // wrong quant type
        const auto prefix = dir / "k2_l1_e44_s0";
        if (!std::filesystem::exists(prefix.string() + ".manifest.txt") ||
            std::filesystem::file_size(prefix.string() + ".down_q6k.bin") != 210)
            code = 5;
        // Dedicated Q4_K gate/up + Q6_K down input-witness smoke.
        std::vector<unsigned char> gate(256 * 144, 0);
        std::vector<unsigned char> up(256 * 144, 0);
        std::vector<unsigned char> down(256 * 210, 0);
        using Deep2::k2_parity_capture::CaptureScalarInputs;
        if (!CaptureScalarInputs(0, 2, 8, 12, gate.data(), gate.size(),
                                 12, up.data(), up.size(), 14,
                                 down.data(), down.size(),
                                 activation.data(), 256, 256))
            code = 7;
        const auto inputStem = dir / "k2_l2_e8_s0_scalar_inputs";
        if (!std::filesystem::exists(inputStem.string() + ".manifest.txt") ||
            std::filesystem::file_size(inputStem.string() + ".gate_q4k.bin") != gate.size() ||
            std::filesystem::file_size(inputStem.string() + ".up_q4k.bin") != up.size() ||
            std::filesystem::file_size(inputStem.string() + ".down_q6k.bin") != down.size())
            code = 8;
        if (CaptureScalarInputs(0, 2, 8, 12, gate.data(), gate.size(),
                                 12, up.data(), up.size(), 14,
                                 down.data(), down.size(),
                                 activation.data(), 256, 256))
            code = 9; // refuse overwrite
        if (CaptureScalarInputs(0, 2, 9, 12, gate.data(), gate.size() - 1,
                                 12, up.data(), up.size(), 14,
                                 down.data(), down.size(),
                                 activation.data(), 256, 256))
            code = 10; // refuse wrong packed geometry
        if (CaptureScalarInputs(0, 2, 10, 12, gate.data(), gate.size(),
                                 12, up.data(), up.size(), 12,
                                 down.data(), down.size(),
                                 activation.data(), 256, 256))
            code = 11; // refuse wrong quantization

        SetCaptureDir("");
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        code = 6;
    }
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    std::cout << (code ? "FAIL" : "PASS") << "\n";
    return code;
}
