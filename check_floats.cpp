#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <iomanip>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: check_floats <file>\n";
        return 1;
    }
    
    std::ifstream f(argv[1], std::ios::binary);
    if (!f) {
        std::cerr << "Failed to open file\n";
        return 1;
    }
    
    // Skip 36-byte header
    f.seekg(36, std::ios::beg);
    
    std::vector<float> data(2048);
    f.read(reinterpret_cast<char*>(data.data()), 2048 * sizeof(float));
    
    std::cout << "First 16 values:\n";
    for (int i = 0; i < 16; ++i) {
        std::cout << "  [" << i << "] = " << data[i] << "\n";
    }
    
    float max_val = data[0];
    size_t argmax = 0;
    for (size_t i = 1; i < data.size(); ++i) {
        if (data[i] > max_val) {
            max_val = data[i];
            argmax = i;
        }
    }
    
    std::cout << "Argmax: " << argmax << " (" << max_val << ")\n";
    
    return 0;
}