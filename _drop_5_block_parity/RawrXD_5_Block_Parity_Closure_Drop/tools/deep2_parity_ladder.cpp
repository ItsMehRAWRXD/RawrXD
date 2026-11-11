#include <algorithm>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace fs = std::filesystem;

struct Cmp {
    double maxAbs = 0.0;
    double rmse = 0.0;
    size_t largest = 0;
    size_t firstBad = static_cast<size_t>(-1);
};

static bool loadF32(const fs::path& p, std::vector<float>& v) {
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    if (!f) return false;
    const auto bytes = f.tellg();
    if (bytes <= 0 || (bytes % static_cast<std::streamoff>(sizeof(float))) != 0) return false;
    v.resize(static_cast<size_t>(bytes / static_cast<std::streamoff>(sizeof(float))));
    f.seekg(0);
    return static_cast<bool>(f.read(reinterpret_cast<char*>(v.data()), bytes));
}

static fs::path findDump(const fs::path& root, const std::string& tag) {
    if (!fs::exists(root)) return {};
    std::vector<fs::path> candidates;
    for (const auto& e : fs::recursive_directory_iterator(root)) {
        if (!e.is_regular_file()) continue;
        const std::string name = e.path().filename().string();
        if (name.find(tag) != std::string::npos &&
            e.path().extension() == ".bin") {
            candidates.push_back(e.path());
        }
    }
    std::sort(candidates.begin(), candidates.end());
    return candidates.empty() ? fs::path{} : candidates.front();
}

static Cmp compare(const std::vector<float>& a, const std::vector<float>& b, double eps) {
    Cmp r;
    long double sq = 0.0L;
    const size_t n = std::min(a.size(), b.size());
    for (size_t i = 0; i < n; ++i) {
        const double d = std::fabs(static_cast<double>(a[i]) - static_cast<double>(b[i]));
        sq += static_cast<long double>(d) * static_cast<long double>(d);
        if (d > r.maxAbs) { r.maxAbs = d; r.largest = i; }
        if (r.firstBad == static_cast<size_t>(-1) && d > eps) r.firstBad = i;
    }
    r.rmse = n ? std::sqrt(static_cast<double>(sq / n)) : 0.0;
    return r;
}

static int argmax(const std::vector<float>& v) {
    if (v.empty()) return -1;
    return static_cast<int>(std::max_element(v.begin(), v.end()) - v.begin());
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: deep2_parity_ladder DEEP2_DUMP_DIR REF_DUMP_DIR [abs_eps]\n";
        return 64;
    }
    const fs::path d2 = argv[1];
    const fs::path ref = argv[2];
    const double eps = argc > 3 ? std::stod(argv[3]) : 1.0e-6;

    const std::vector<std::string> steps = {
        "FFN_INP_10",
        "FFN_NORM_10",
        "FFN_GATE_10",
        "FFN_UP_10",
        "FFN_ACT_10",
        "FFN_DOWN_10",
        "LAYER_OUT_10",
        "LAYER_OUT_12",
        "LAYER_OUT_16",
        "LAYER_OUT_21",
        "FINAL_NORM",
        "LOGITS"
    };

    std::cout << "DEEP2_PARITY_LADDER\n";
    std::cout << "ABS_EPS=" << eps << "\n";

    for (const auto& tag : steps) {
        const fs::path aPath = findDump(d2, tag);
        const fs::path bPath = findDump(ref, tag);

        if (aPath.empty() || bPath.empty()) {
            std::cout << tag << " LOAD_FAIL"
                      << " deep2=" << (aPath.empty() ? "missing" : aPath.string())
                      << " ref=" << (bPath.empty() ? "missing" : bPath.string()) << "\n";
            std::cout << "FIRST_FAIL=" << tag << "\n";
            return 2;
        }

        std::vector<float> a, b;
        if (!loadF32(aPath, a) || !loadF32(bPath, b) || a.size() != b.size()) {
            std::cout << tag << " SHAPE_OR_READ_FAIL"
                      << " d2_n=" << a.size() << " ref_n=" << b.size() << "\n";
            std::cout << "FIRST_FAIL=" << tag << "\n";
            return 3;
        }

        const Cmp c = compare(a, b, eps);
        const bool pass = c.maxAbs <= eps;
        std::cout << tag
                  << " gate=" << (pass ? "PASS" : "FAIL")
                  << " n=" << a.size()
                  << " max_abs=" << c.maxAbs
                  << " rmse=" << c.rmse
                  << " largest=" << c.largest;
        if (c.firstBad != static_cast<size_t>(-1))
            std::cout << " first_bad=" << c.firstBad;
        if (tag == "LOGITS")
            std::cout << " argmax_d2=" << argmax(a) << " argmax_ref=" << argmax(b);
        std::cout << "\n";

        if (!pass) {
            std::cout << "FIRST_FAIL=" << tag << "\n";
            return 1;
        }

        if (tag == "LOGITS" && argmax(a) != argmax(b)) {
            std::cout << "FIRST_FAIL=ARGMAX\n";
            return 4;
        }
    }

    std::cout << "FIRST_FAIL=none\n";
    std::cout << "BLOCK4_DEEP2_PARITY=PASS\n";
    return 0;
}
