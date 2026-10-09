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

struct RefTensorHeader {
    uint32_t magic;
    uint32_t version;
    int32_t layer;
    int32_t position;
    uint32_t name_len;
    std::string name;
    uint32_t shape_count;
    std::vector<int64_t> shape;
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

bool readRefHeader(std::ifstream &f, RefTensorHeader &header) {
    f.read(reinterpret_cast<char*>(&header.magic), 4);
    if (!f) return false;
    f.read(reinterpret_cast<char*>(&header.version), 4);
    f.read(reinterpret_cast<char*>(&header.layer), 4);
    f.read(reinterpret_cast<char*>(&header.position), 4);
    f.read(reinterpret_cast<char*>(&header.name_len), 4);
    
    header.name.resize(header.name_len);
    f.read(&header.name[0], header.name_len);
    
    f.read(reinterpret_cast<char*>(&header.shape_count), 4);
    header.shape.resize(header.shape_count);
    f.read(reinterpret_cast<char*>(header.shape.data()), header.shape_count * 8);
    
    return true;
}

size_t nativeTensorElements(const NativeTensorHeader &header) {
    return static_cast<size_t>(header.element_count);
}

size_t refTensorElements(const RefTensorHeader &header) {
    size_t nelements = 1;
    for (auto dim : header.shape) nelements *= dim;
    return nelements;
}

void compareTensor(const std::string &native_path, const std::string &ref_path, const std::string &label) {
    std::ifstream native(native_path, std::ios::binary);
    std::ifstream ref(ref_path, std::ios::binary);
    
    if (!native || !ref) {
        std::cerr << "Failed to open files for " << label << "\n";
        return;
    }
    
    NativeTensorHeader native_header;
    RefTensorHeader ref_header;
    
    if (!readNativeHeader(native, native_header) || !readRefHeader(ref, ref_header)) {
        std::cerr << "Failed to read headers for " << label << "\n";
        return;
    }
    
    size_t native_elements = nativeTensorElements(native_header);
    size_t ref_elements = refTensorElements(ref_header);
    
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
    
    std::cout << label << ":\n";
    std::cout << "  Native: op=" << native_header.op_id << ", layer=" << native_header.layer << ", pos=" << native_header.position << ", elements=" << native_elements << "\n";
    std::cout << "  Ref: layer=" << ref_header.layer << ", pos=" << ref_header.position << ", elements=" << ref_elements << "\n";
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
    std::string native_dir = "F:\\rawrxd\\evidence\\NUGVERSE_ESTIMATOR_001\\native_diff";
    std::string ref_dir = "F:\\rawrxd\\evidence\\NUGVERSE_ESTIMATOR_001\\ref_capture_v9";
    
    // MLA Attention sub-operations at position 0, layer 0
    std::vector<std::tuple<std::string, std::string, std::string>> tensors = {
        // native pattern, ref name, label
        {"op2_MlaDecompress_Input", "kv_cmpr", "Layer 0: MLA Decompress Input (kv_cmpr)"},
        {"op2_MLA_CacheKV_Prefix_kv_prefix", "kv_cmpr", "Layer 0: MLA KV Cache Prefix (kv_cmpr)"},
        {"op2_MlaDecompress_Output", "q", "Layer 0: MLA Decompress Output (q)"},
        {"op3_Linear_Output", "q", "Layer 0: Q Projection (q)"},
        {"op2_MlaDecompress_Output", "k_pe", "Layer 0: K PE (k_pe)"},
        {"op2_MLA_CacheKV_Prefix_kv_prefix", "k_pe", "Layer 0: K PE from Cache (k_pe)"},
        {"op3_Linear_Output", "q_pe", "Layer 0: Q PE (q_pe)"},
        {"op4_Attention_Output", "attn_out", "Layer 0: Attention Output (attn_out)"},
    };
    
    for (auto &t : tensors) {
        std::string native_pattern = std::get<0>(t);
        std::string ref_name = std::get<1>(t);
        std::string label = std::get<2>(t);
        
        // Find native file matching pattern
        std::string native_file;
        for (auto &entry : std::filesystem::directory_iterator(native_dir)) {
            std::string name = entry.path().filename().string();
            if (name.find(native_pattern) != std::string::npos && name.find("_p0_") != std::string::npos) {
                native_file = entry.path().string();
                break;
            }
        }
        
        if (native_file.empty()) {
            std::cout << label << ": Native file not found for pattern " << native_pattern << "\n\n";
            continue;
        }
        
        std::string ref_path = ref_dir + "\\ref_l00_p00_" + ref_name + ".bin";
        if (!std::filesystem::exists(ref_path)) {
            std::cout << label << ": Ref file not found: " << ref_path << "\n\n";
            continue;
        }
        
        compareTensor(native_file, ref_path, label);
    }
    
    return 0;
}