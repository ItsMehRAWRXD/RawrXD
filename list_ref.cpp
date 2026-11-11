#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cmath>
#include <algorithm>
#include <iomanip>
#include <filesystem>

void printRefStats(const std::string &path, const std::string &label) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        std::cerr << "Failed to open " << path << "\n";
        return;
    }
    
    f.seekg(0, std::ios::end);
    size_t file_size = f.tellg();
    f.seekg(0, std::ios::beg);
    size_t elements = file_size / sizeof(float);
    
    std::vector<float> data(elements);
    f.read(reinterpret_cast<char*>(data.data()), elements * sizeof(float));
    
    bool finite = true;
    size_t argmax = 0;
    float max_val = data[0];
    for (size_t i = 0; i < elements; ++i) {
        if (!std::isfinite(data[i])) finite = false;
        if (data[i] > max_val) { max_val = data[i]; argmax = i; }
    }
    
    std::cout << label << ": elements=" << elements << ", finite=" << (finite ? "YES" : "NO") 
              << ", argmax=" << argmax << ", max=" << max_val << "\n";
}

int main(int argc, char** argv) {
    std::string ref_dir = "F:\\rawrxd\\evidence\\NUGVERSE_ESTIMATOR_001\\ref_capture";
    
    for (int pos = 0; pos < 4; ++pos) {
        std::string path = ref_dir + "\\ref_logits_pos" + std::to_string(pos) + ".bin";
        printRefStats(path, "ref_pos" + std::to_string(pos));
    }
    
    return 0;
}