// Benchmark actual tensor byte distributions without confusing codec success
// with model quality. Input is a raw tensor payload extracted from GGUF;
// no GGUF header, tensor offsets, or quantization metadata are modified.
#include "../../src/deep2/NativeTensorCompression.hpp"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

using namespace RawrXD::TensorCompression;

static const char* Name(Encoding e) {
    switch (e) {
    case Encoding::Raw: return "raw";
    case Encoding::RLE: return "rle";
    case Encoding::F16: return "f16";
    case Encoding::BF16: return "bf16";
    case Encoding::LZ4: return "lz4";
    case Encoding::ShuffleLZ4: return "shuffle-lz4";
    }
    return "unknown";
}

static void Measure(const std::string& name, const std::vector<uint8_t>& input,
                    bool allowLossy, double tolerance) {
    const auto t0 = std::chrono::steady_clock::now();
    auto encoded = Encode(input.data(), input.size(), allowLossy,
                          static_cast<float>(tolerance), allowLossy);
    const auto t1 = std::chrono::steady_clock::now();
    auto decoded = Decode(encoded);
    const auto t2 = std::chrono::steady_clock::now();
    if (decoded.size() != input.size())
        throw std::runtime_error("decoded size mismatch");
    double maxError = 0;
    if (encoded.encoding == Encoding::F16 || encoded.encoding == Encoding::BF16) {
        if (input.size() % 4) throw std::runtime_error("invalid float alignment");
        for (size_t i = 0; i < input.size(); i += 4) {
            float before, after;
            std::memcpy(&before, input.data() + i, 4);
            std::memcpy(&after, decoded.data() + i, 4);
            const double err = std::abs(double(before) - double(after));
            if (err > maxError) maxError = err;
            if (!(err <= tolerance))
                throw std::runtime_error("quantization error exceeds tolerance");
        }
    } else if (decoded != input) {
        throw std::runtime_error("lossless roundtrip mismatch");
    }
    const auto ms = [](auto a, auto b) {
        return std::chrono::duration<double, std::milli>(b - a).count();
    };
    const double ratio = input.empty() ? 1.0 :
        double(encoded.payload.size()) / double(input.size());
    std::cout << name << ",codec=" << Name(encoded.encoding)
              << ",raw_bytes=" << input.size()
              << ",encoded_bytes=" << encoded.payload.size()
              << ",resident_ratio=" << std::fixed << std::setprecision(4) << ratio
              << ",encode_ms=" << ms(t0,t1)
              << ",decode_ms=" << ms(t1,t2)
              << ",max_abs_error=" << maxError << "\n";
}

int main(int argc, char** argv) {
    try {
        if (argc < 2 || argc > 4) {
            std::cerr << "usage: tensor_codec_benchmark <raw-tensor-file> [f32-lossy-tolerance] [max-input-MiB]\n";
            return 2;
        }
        const double tolerance = argc >= 3 ? std::stod(argv[2]) : 0.0;
        const bool allowLossy = argc >= 3;
        const uint64_t maxMiB = argc >= 4 ? std::stoull(argv[3]) : 256ull;
        if (maxMiB == 0 || maxMiB > 4096 ||
            maxMiB > std::numeric_limits<size_t>::max() / (1024ull * 1024ull))
            throw std::invalid_argument("invalid input limit");
        if (!(tolerance >= 0.0 && tolerance <= std::numeric_limits<float>::max()))
            throw std::invalid_argument("invalid tolerance");
        std::ifstream in(argv[1], std::ios::binary | std::ios::ate);
        if (!in) throw std::runtime_error("cannot open input");
        const auto length = in.tellg();
        if (length < 0 || uint64_t(length) > maxMiB * 1024ull * 1024ull)
            throw std::runtime_error("input exceeds limit");
        std::vector<uint8_t> input(static_cast<size_t>(length));
        in.seekg(0);
        if (!input.empty() && !in.read(reinterpret_cast<char*>(input.data()),
                                       static_cast<std::streamsize>(input.size())))
            throw std::runtime_error("input read failed");
        Measure("lossless", input, false, 0.0);
        if (allowLossy) {
            if (input.size() % 4) throw std::invalid_argument("F32 size must be multiple of 4");
            Measure("f32-tolerance", input, true, tolerance);
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << "\n";
        return 1;
    }
}
