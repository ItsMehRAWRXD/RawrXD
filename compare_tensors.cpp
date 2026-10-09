#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cmath>
#include <algorithm>
#include <iomanip>
#include <filesystem>

struct NativeTensorHeader {
    uint32_t op_id;
    int32_t layer;
    int32_t position;
    int64_t metadata0;
    uint64_t element_count;
    uint64_t element_count2;
};

bool readNativeHeader(std::ifstream &f, NativeTensorHeader &header) {
    f.read(reinterpret_cast<char*>(&header.op_id), 4);
    if (!f) return false;
    f.read(reinterpret_cast<char*>(&header.layer), 4);
    f.read(reinterpret_cast<char*>(&header.position), 4);
    f.read(reinterpret_cast<char*>(&header.metadata0), 8);
    f.read(reinterpret_cast<char*>(&header.element_count), 8);
    f.read(reinterpret_cast<char*>(&header.element_count2), 8);
    return true;
}

size_t tensorElements(const NativeTensorHeader &header) {
    return static_cast<size_t>(header.element_count);
}

bool compareTensors(const std::string &native_path, const std::string &ref_path) {
    std::ifstream native(native_path, std::ios::binary);
    std::ifstream ref(ref_path, std::ios::binary);
    
    if (!native || !ref) {
        std::cerr << "Failed to open files\n";
        return false;
    }
    
    NativeTensorHeader native_header;
    if (!readNativeHeader(native, native_header)) {
        std::cerr << "Failed to read native header\n";
        return false;
    }
    
    size_t native_elements = tensorElements(native_header);
    
    // Reference file is raw float32 data
    ref.seekg(0, std::ios::end);
    size_t ref_file_size = ref.tellg();
    ref.seekg(0, std::ios::beg);
    size_t ref_elements = ref_file_size / sizeof(float);
    
    if (native_elements != ref_elements) {
        std::cout << "Shape mismatch: native=" << native_elements << " ref=" << ref_elements << "\n";
        return false;
    }
    
    std::vector<float> native_data(native_elements);
    std::vector<float> ref_data(ref_elements);
    
    native.read(reinterpret_cast<char*>(native_data.data()), native_elements * sizeof(float));
    ref.read(reinterpret_cast<char*>(ref_data.data()), ref_elements * sizeof(float));
    
    // Check for NaN/Inf
    bool native_finite = true, ref_finite = true;
    for (float v : native_data) if (!std::isfinite(v)) native_finite = false;
    for (float v : ref_data) if (!std::isfinite(v)) ref_finite = false;
    
    // Compute metrics
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
    
    // Top-10 overlap
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
    
    std::cout << "Tensor: op" << native_header.op_id << " (layer=" << native_header.layer << ", pos=" << native_header.position << ")\n";
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
    
    return argmax_native == argmax_ref;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: compare_tensors <native_dir> <ref_dir>\n";
        return 1;
    }
    
    std::string native_dir = argv[1];
    std::string ref_dir = argv[2];
    
    // Compare position 2 logits
    std::string native_logits = native_dir + "/rec_000461_op299_Output_l4294967295_p2_output.bin";
    std::string ref_logits = ref_dir + "/ref_logits_pos2.bin";
    
    std::cout << "=== Comparing position 2 logits ===\n";
    compareTensors(native_logits, ref_logits);
    
    return 0;
}