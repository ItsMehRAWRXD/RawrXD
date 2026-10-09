#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cmath>
#include <algorithm>
#include <iomanip>
#include <filesystem>

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

size_t refTensorElements(const RefTensorHeader &header) {
    size_t nelements = 1;
    for (auto dim : header.shape) nelements *= dim;
    return nelements;
}

void printTensorStats(const std::string &path, const std::string &label) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        std::cerr << "Failed to open " << path << "\n";
        return;
    }
    
    RefTensorHeader header;
    if (!readRefHeader(f, header)) {
        std::cerr << "Failed to read header from " << path << "\n";
        return;
    }
    
    size_t elements = refTensorElements(header);
    std::vector<float> data(elements);
    f.read(reinterpret_cast<char*>(data.data()), elements * sizeof(float));
    
    bool finite = true;
    size_t argmax = 0;
    float max_val = data[0], min_val = data[0];
    double sum = 0, sum_sq = 0;
    for (size_t i = 0; i < elements; ++i) {
        if (!std::isfinite(data[i])) finite = false;
        if (data[i] > max_val) { max_val = data[i]; argmax = i; }
        if (data[i] < min_val) min_val = data[i];
        sum += data[i];
        sum_sq += static_cast<double>(data[i]) * data[i];
    }
    
    double mean = sum / elements;
    double variance = sum_sq / elements - mean * mean;
    double stddev = std::sqrt(std::max(0.0, variance));
    
    std::cout << label << ":\n";
    std::cout << "  Layer: " << header.layer << ", Pos: " << header.position << ", Name: " << header.name << "\n";
    std::cout << "  Elements: " << elements << "\n";
    std::cout << "  Finite: " << (finite ? "YES" : "NO") << "\n";
    std::cout << "  Argmax: " << argmax << " (" << max_val << ")\n";
    std::cout << "  Min: " << min_val << "\n";
    std::cout << "  Mean: " << mean << "\n";
    std::cout << "  StdDev: " << stddev << "\n";
    std::cout << "\n";
}

int main() {
    std::string ref_dir = "F:\\rawrxd\\evidence\\NUGVERSE_ESTIMATOR_001\\ref_capture_v3";
    
    for (int pos = 0; pos < 4; ++pos) {
        std::string path = ref_dir + "\\ref_l-1_p0" + std::to_string(pos) + "_inp_embd.bin";
        printTensorStats(path, "ref_l-1_p0" + std::to_string(pos) + "_inp_embd");
    }
    
    return 0;
}