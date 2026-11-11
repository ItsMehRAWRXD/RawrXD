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

void printTensorStats(const std::string &path, const std::string &label) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        std::cerr << "Failed to open " << path << "\n";
        return;
    }
    
    NativeTensorHeader header;
    if (!readNativeHeader(f, header)) {
        std::cerr << "Failed to read header from " << path << "\n";
        return;
    }
    
    size_t elements = tensorElements(header);
    std::vector<float> data(elements);
    f.read(reinterpret_cast<char*>(data.data()), elements * sizeof(float));
    
    bool finite = true;
    size_t argmax = 0;
    float max_val = data[0];
    for (size_t i = 0; i < elements; ++i) {
        if (!std::isfinite(data[i])) finite = false;
        if (data[i] > max_val) { max_val = data[i]; argmax = i; }
    }
    
    std::cout << label << ": op=" << header.op_id << ", layer=" << header.layer << ", pos=" << header.position 
              << ", elements=" << elements << ", finite=" << (finite ? "YES" : "NO") 
              << ", argmax=" << argmax << ", max=" << max_val << "\n";
}

int main(int argc, char** argv) {
    std::string native_dir = "F:\\rawrxd\\evidence\\NUGVERSE_ESTIMATOR_001\\differential_pos2_focused";
    
    // Find all op299 files
    for (auto &entry : std::filesystem::directory_iterator(native_dir)) {
        std::string name = entry.path().filename().string();
        if (name.find("op299") != std::string::npos) {
            printTensorStats(entry.path().string(), name);
        }
    }
    
    return 0;
}