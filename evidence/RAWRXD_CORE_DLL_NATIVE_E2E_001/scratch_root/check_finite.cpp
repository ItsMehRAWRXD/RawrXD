// Check for non-finite values in a binary file
#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cmath>
#include <cstdint>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <file.bin>" << std::endl;
        return 1;
    }
    
    std::ifstream f(argv[1], std::ios::binary);
    if (!f) {
        std::cerr << "Failed to open: " << argv[1] << std::endl;
        return 1;
    }
    
    f.seekg(0, std::ios::end);
    size_t size = f.tellg();
    f.seekg(0, std::ios::beg);
    
    size_t count = size / sizeof(float);
    std::vector<float> data(count);
    f.read(reinterpret_cast<char*>(data.data()), size);
    
    size_t nanCount = 0, infCount = 0, negInfCount = 0;
    float minVal = INFINITY, maxVal = -INFINITY;
    
    for (size_t i = 0; i < count; ++i) {
        if (std::isnan(data[i])) nanCount++;
        else if (std::isinf(data[i])) {
            if (data[i] > 0) infCount++;
            else negInfCount++;
        } else {
            if (data[i] < minVal) minVal = data[i];
            if (data[i] > maxVal) maxVal = data[i];
        }
    }
    
    std::cout << "File: " << argv[1] << std::endl;
    std::cout << "Count: " << count << std::endl;
    std::cout << "NaN: " << nanCount << std::endl;
    std::cout << "Inf: " << infCount << std::endl;
    std::cout << "-Inf: " << negInfCount << std::endl;
    std::cout << "Min: " << minVal << std::endl;
    std::cout << "Max: " << maxVal << std::endl;
    
    // Print first 20 values
    std::cout << "First 20: ";
    for (size_t i = 0; i < std::min<size_t>(20, count); ++i) {
        std::cout << data[i] << " ";
    }
    std::cout << std::endl;
    
    return 0;
}