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

void loadAndPrint(const std::string &path, const std::string &label, bool is_native, bool is_raw = false) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        std::cerr << "Failed to open " << path << "\n";
        return;
    }
    
    std::vector<float> data;
    
    if (is_raw) {
        f.seekg(0, std::ios::end);
        size_t file_size = f.tellg();
        f.seekg(0, std::ios::beg);
        size_t elements = file_size / sizeof(float);
        data.resize(elements);
        f.read(reinterpret_cast<char*>(data.data()), elements * sizeof(float));
    } else if (is_native) {
        NativeTensorHeader header;
        if (!readNativeHeader(f, header)) {
            std::cerr << "Failed to read native header\n";
            return;
        }
        size_t elements = nativeTensorElements(header);
        data.resize(elements);
        f.read(reinterpret_cast<char*>(data.data()), elements * sizeof(float));
    } else {
        RefTensorHeader header;
        if (!readRefHeader(f, header)) {
            std::cerr << "Failed to read ref header\n";
            return;
        }
        size_t elements = refTensorElements(header);
        data.resize(elements);
        f.read(reinterpret_cast<char*>(data.data()), elements * sizeof(float));
    }
    
    bool finite = true;
    size_t argmax = 0;
    float max_val = data[0], min_val = data[0];
    double sum = 0, sum_sq = 0;
    for (size_t i = 0; i < data.size(); ++i) {
        if (!std::isfinite(data[i])) finite = false;
        if (data[i] > max_val) { max_val = data[i]; argmax = i; }
        if (data[i] < min_val) min_val = data[i];
        sum += data[i];
        sum_sq += static_cast<double>(data[i]) * data[i];
    }
    
    double mean = sum / data.size();
    double variance = sum_sq / data.size() - mean * mean;
    double stddev = std::sqrt(std::max(0.0, variance));
    
    std::cout << label << ":\n";
    std::cout << "  Elements: " << data.size() << "\n";
    std::cout << "  Finite: " << (finite ? "YES" : "NO") << "\n";
    std::cout << "  Argmax: " << argmax << " (" << max_val << ")\n";
    std::cout << "  Min: " << min_val << "\n";
    std::cout << "  Mean: " << mean << "\n";
    std::cout << "  StdDev: " << stddev << "\n";
    std::cout << "\n";
}

int main() {
    // Native op0 (token embedding)
    loadAndPrint("F:\\rawrxd\\evidence\\NUGVERSE_ESTIMATOR_001\\native_diff\\rec_000000_op0_Linear_Output_l4294967295_p0_output.bin", 
                 "Native op0 (token embedding)", true);
    
    // Reference inp_embd
    loadAndPrint("F:\\rawrxd\\evidence\\NUGVERSE_ESTIMATOR_001\\ref_capture_v3\\ref_l-1_p00_inp_embd.bin", 
                 "Reference inp_embd", false);
    
    // Direct llama.cpp embeddings (final hidden state)
    loadAndPrint("F:\\rawrxd\\direct_embd_token1.bin", 
                 "Direct llama.cpp (final hidden)", true, true);
    
    // Also compare native op298 (result_norm) with direct
    loadAndPrint("F:\\rawrxd\\evidence\\NUGVERSE_ESTIMATOR_001\\native_diff\\rec_000460_op298_RMSNorm_Output_l4294967295_p2_output.bin", 
                 "Native op298 (result_norm, pos2)", true);
    
    return 0;
}