#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cmath>
#include <algorithm>
#include <iomanip>
#include <filesystem>

void compareLogits(const std::string &native_path, const std::string &ref_path, const std::string &label) {
    std::ifstream native(native_path, std::ios::binary);
    std::ifstream ref(ref_path, std::ios::binary);
    
    if (!native || !ref) {
        std::cerr << "Failed to open files for " << label << "\n";
        return;
    }
    
    native.seekg(0, std::ios::end);
    size_t native_size = native.tellg();
    native.seekg(0, std::ios::beg);
    size_t native_elements = native_size / sizeof(float);
    
    ref.seekg(0, std::ios::end);
    size_t ref_size = ref.tellg();
    ref.seekg(0, std::ios::beg);
    size_t ref_elements = ref_size / sizeof(float);
    
    if (native_elements != ref_elements) {
        std::cout << label << ": Shape mismatch native=" << native_elements << " ref=" << ref_elements << "\n";
        return;
    }
    
    std::vector<float> native_data(native_elements);
    std::vector<float> ref_data(ref_elements);
    
    native.read(reinterpret_cast<char*>(native_data.data()), native_elements * sizeof(float));
    ref.read(reinterpret_cast<char*>(ref_data.data()), ref_elements * sizeof(float));
    
    bool native_finite = true, ref_finite = true;
    for (float v : native_data) if (!std::isfinite(v)) native_finite = false;
    for (float v : ref_data) if (!std::isfinite(v)) ref_finite = false;
    
    double sum_sq_diff = 0.0;
    double sum_native_sq = 0.0;
    double sum_ref_sq = 0.0;
    double sum_native_ref = 0.0;
    double max_abs_diff = 0.0;
    size_t argmax_native = 0, argmax_ref = 0;
    float max_native = native_data[0], max_ref = ref_data[0];
    
    for (size_t i = 0; i < native_elements; ++i) {
        float diff = native_data[i] - ref_data[i];
        double abs_diff = std::abs(diff);
        sum_sq_diff += abs_diff * abs_diff;
        sum_native_sq += static_cast<double>(native_data[i]) * native_data[i];
        sum_ref_sq += static_cast<double>(ref_data[i]) * ref_data[i];
        sum_native_ref += static_cast<double>(native_data[i]) * ref_data[i];
        if (abs_diff > max_abs_diff) max_abs_diff = abs_diff;
        if (native_data[i] > max_native) { max_native = native_data[i]; argmax_native = i; }
        if (ref_data[i] > max_ref) { max_ref = ref_data[i]; argmax_ref = i; }
    }
    
    double rmse = std::sqrt(sum_sq_diff / native_elements);
    double cosine = sum_native_ref / (std::sqrt(sum_native_sq) * std::sqrt(sum_ref_sq));
    
    std::vector<std::pair<float, size_t>> native_top, ref_top;
    native_top.reserve(native_elements);
    ref_top.reserve(ref_elements);
    for (size_t i = 0; i < native_elements; ++i) {
        native_top.emplace_back(native_data[i], i);
        ref_top.emplace_back(ref_data[i], i);
    }
    std::sort(native_top.begin(), native_top.end(), [](auto &a, auto &b) { return a.first > b.first; });
    std::sort(ref_top.begin(), ref_top.end(), [](auto &a, auto &b) { return a.first > b.first; });
    
    int top10_overlap = 0;
    for (int i = 0; i < 10 && i < (int)native_elements; ++i) {
        for (int j = 0; j < 10 && j < (int)ref_elements; ++j) {
            if (native_top[i].second == ref_top[j].second) {
                top10_overlap++;
                break;
            }
        }
    }
    
    std::cout << "=== " << label << " ===\n";
    std::cout << "  Elements: " << native_elements << "\n";
    std::cout << "  Native finite: " << (native_finite ? "YES" : "NO") << "\n";
    std::cout << "  Ref finite: " << (ref_finite ? "YES" : "NO") << "\n";
    std::cout << "  Argmax native: " << argmax_native << " (" << max_native << ")\n";
    std::cout << "  Argmax ref: " << argmax_ref << " (" << max_ref << ")\n";
    std::cout << "  Argmax match: " << (argmax_native == argmax_ref ? "YES" : "NO") << "\n";
    std::cout << "  RMSE: " << rmse << "\n";
    std::cout << "  Cosine: " << cosine << "\n";
    std::cout << "  Max abs diff: " << max_abs_diff << "\n";
    std::cout << "  Top-10 overlap: " << top10_overlap << "/10\n";
    std::cout << "\n";
}

int main() {
    std::string native_dir = "F:\\rawrxd\\evidence\\NUGVERSE_ESTIMATOR_001\\native_capture";
    std::string ref_dir = "F:\\rawrxd\\evidence\\NUGVERSE_ESTIMATOR_001\\ref_capture_full";
    
    for (int pos = 0; pos < 4; ++pos) {
        std::string native_path = native_dir + "\\native_tf_logits_pos" + std::to_string(pos) + ".bin";
        std::string ref_path = ref_dir + "\\ref_logits_pos" + std::to_string(pos) + ".bin";
        compareLogits(native_path, ref_path, "Position " + std::to_string(pos));
    }
    
    return 0;
}