// Compare two files, ignoring NaN positions
#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cmath>
#include <cstdint>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <file1.bin> <file2.bin>" << std::endl;
        return 1;
    }
    
    auto readFile = [](const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return std::vector<float>{};
        f.seekg(0, std::ios::end);
        size_t size = f.tellg();
        f.seekg(0, std::ios::beg);
        std::vector<float> data(size / sizeof(float));
        f.read(reinterpret_cast<char*>(data.data()), size);
        return data;
    };
    
    auto a = readFile(argv[1]);
    auto b = readFile(argv[2]);
    
    if (a.size() != b.size()) {
        std::cerr << "Size mismatch: " << a.size() << " vs " << b.size() << std::endl;
        return 1;
    }
    
    float dotProduct = 0, aNormSq = 0, bNormSq = 0, mse = 0, maxDiff = 0;
    uint32_t argmaxA = 0, argmaxB = 0;
    float maxA = a[0], maxB = b[0];
    size_t validCount = 0;
    
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::isnan(a[i]) || std::isnan(b[i]) || std::isinf(a[i]) || std::isinf(b[i])) {
            continue;
        }
        validCount++;
        dotProduct += a[i] * b[i];
        aNormSq += a[i] * a[i];
        bNormSq += b[i] * b[i];
        float diff = a[i] - b[i];
        mse += diff * diff;
        float absDiff = std::abs(diff);
        if (absDiff > maxDiff) maxDiff = absDiff;
        if (a[i] > maxA) { maxA = a[i]; argmaxA = i; }
        if (b[i] > maxB) { maxB = b[i]; argmaxB = i; }
    }
    
    float rmse = std::sqrt(mse / validCount);
    float aNorm = std::sqrt(aNormSq);
    float bNorm = std::sqrt(bNormSq);
    float cosine = (aNorm > 0 && bNorm > 0) ? dotProduct / (aNorm * bNorm) : 0;
    
    std::cout << "Valid elements: " << validCount << "/" << a.size() << std::endl;
    std::cout << "Cosine: " << cosine << std::endl;
    std::cout << "RMSE: " << rmse << std::endl;
    std::cout << "Max Diff: " << maxDiff << std::endl;
    std::cout << "Argmax A: " << argmaxA << " (" << maxA << ")" << std::endl;
    std::cout << "Argmax B: " << argmaxB << " (" << maxB << ")" << std::endl;
    
    return 0;
}