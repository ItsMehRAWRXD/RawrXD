#include "RGUFFormat.hpp"
#include "RGUFLoader.hpp"
#include "RGUFWriter.hpp"
#include "RGUFPlatform.hpp"
#include "RGUFQuant.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <fstream>

static void print_usage(const char* prog) {
    std::cerr << "Usage:\n"
              << "  " << prog << " pack <input.gguf> <output.rguf> [key-hex]\n"
              << "  " << prog << " inspect <file.rguf>\n"
              << "  " << prog << " quant-fp32 <input.bin> <output.q4>\n"
              << "  " << prog << " dequant-q4 <input.q4> <output.bin> <count>\n";
}

static bool parse_hex_key(const char* hex, uint8_t out[32]) {
    size_t len = std::strlen(hex);
    if (len != 64) return false;
    for (size_t i = 0; i < 32; ++i) {
        unsigned int byte = 0;
        if (std::sscanf(hex + 2*i, "%2x", &byte) != 1) return false;
        out[i] = static_cast<uint8_t>(byte);
    }
    return true;
}

int main(int argc, char** argv) {
    if (argc < 2) { print_usage(argv[0]); return 1; }
    const char* cmd = argv[1];

    if (std::strcmp(cmd, "pack") == 0) {
        if (argc < 4 || argc > 5) { print_usage(argv[0]); return 1; }
        rguf::WriterConfig cfg{};
        if (argc == 5) {
            cfg.encrypt = true;
            if (!parse_hex_key(argv[4], cfg.key)) {
                std::cerr << "Invalid key: must be 64 hex chars\n";
                return 1;
            }
        }
        rguf::Writer w;
        std::string err;
        if (!w.pack(argv[2], argv[3], cfg, err)) {
            std::cerr << "Pack failed: " << err << "\n";
            return 1;
        }
        std::cout << "Packed " << argv[2] << " -> " << argv[3] << "\n";
        return 0;
    }

    if (std::strcmp(cmd, "inspect") == 0) {
        if (argc != 3) { print_usage(argv[0]); return 1; }
        rguf::Model m;
        std::string err;
        if (!m.open(argv[2], err)) {
            std::cerr << "Inspect failed: " << err << "\n";
            return 1;
        }
        std::cout << "RGUF: " << argv[2] << "\n";
        return 0;
    }

    if (std::strcmp(cmd, "quant-fp32") == 0) {
        if (argc != 4) { print_usage(argv[0]); return 1; }
        std::ifstream in(argv[2], std::ios::binary);
        if (!in) { std::cerr << "Cannot open " << argv[2] << "\n"; return 1; }
        std::vector<float> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        size_t count = data.size();
        std::vector<uint8_t> out;
        rguf::quantize_q4(data.data(), count, out);
        std::ofstream ofs(argv[3], std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(out.data()), out.size());
        std::cout << "Quantized " << count << " floats to Q4 (" << out.size() << " bytes)\n";
        return 0;
    }

    if (std::strcmp(cmd, "dequant-q4") == 0) {
        if (argc != 5) { print_usage(argv[0]); return 1; }
        size_t count = std::stoull(argv[4]);
        std::ifstream in(argv[2], std::ios::binary);
        if (!in) { std::cerr << "Cannot open " << argv[2] << "\n"; return 1; }
        std::vector<uint8_t> src((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        std::vector<float> dst(count);
        rguf::dequantize_q4(src.data(), count, dst.data());
        std::ofstream ofs(argv[3], std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(dst.data()), dst.size() * sizeof(float));
        std::cout << "Dequantized Q4 to " << count << " floats\n";
        return 0;
    }

    print_usage(argv[0]);
    return 1;
}
