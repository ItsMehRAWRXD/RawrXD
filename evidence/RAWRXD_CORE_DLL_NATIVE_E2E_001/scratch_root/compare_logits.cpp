// Logits comparison tool - compares native vs reference logits
#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cmath>
#include <algorithm>
#include <cstdint>
#include <cstdio>

struct CompareResult {
    size_t length;
    bool allFinite;
    float cosine;
    float rmse;
    float maxAbsDiff;
    uint32_t argmaxNative;
    uint32_t argmaxRef;
    int top10Overlap;
};

CompareResult compareLogits(const std::string& nativePath, const std::string& refPath) {
    CompareResult result = {};
    
    // Read native logits
    std::ifstream nativeFile(nativePath, std::ios::binary);
    if (!nativeFile) {
        std::cerr << "Failed to open: " << nativePath << std::endl;
        return result;
    }
    nativeFile.seekg(0, std::ios::end);
    size_t nativeSize = nativeFile.tellg();
    nativeFile.seekg(0, std::ios::beg);
    
    // Read reference logits
    std::ifstream refFile(refPath, std::ios::binary);
    if (!refFile) {
        std::cerr << "Failed to open: " << refPath << std::endl;
        return result;
    }
    refFile.seekg(0, std::ios::end);
    size_t refSize = refFile.tellg();
    refFile.seekg(0, std::ios::beg);
    
    if (nativeSize != refSize) {
        std::cerr << "Size mismatch: native=" << nativeSize << " ref=" << refSize << std::endl;
        return result;
    }
    
    result.length = nativeSize / sizeof(float);
    
    std::vector<float> native(result.length);
    std::vector<float> ref(result.length);
    
    nativeFile.read(reinterpret_cast<char*>(native.data()), nativeSize);
    refFile.read(reinterpret_cast<char*>(ref.data()), refSize);
    
    // Check finiteness and compute stats
    result.allFinite = true;
    float dotProduct = 0.0f;
    float nativeNormSq = 0.0f;
    float refNormSq = 0.0f;
    float mse = 0.0f;
    result.maxAbsDiff = 0.0f;
    result.argmaxNative = 0;
    result.argmaxRef = 0;
    float maxNative = native[0];
    float maxRef = ref[0];
    
    for (size_t i = 0; i < result.length; ++i) {
        if (!std::isfinite(native[i]) || !std::isfinite(ref[i])) {
            result.allFinite = false;
        }
        
        dotProduct += native[i] * ref[i];
        nativeNormSq += native[i] * native[i];
        refNormSq += ref[i] * ref[i];
        
        float diff = native[i] - ref[i];
        mse += diff * diff;
        
        float absDiff = std::abs(diff);
        if (absDiff > result.maxAbsDiff) {
            result.maxAbsDiff = absDiff;
        }
        
        if (native[i] > maxNative) {
            maxNative = native[i];
            result.argmaxNative = static_cast<uint32_t>(i);
        }
        if (ref[i] > maxRef) {
            maxRef = ref[i];
            result.argmaxRef = static_cast<uint32_t>(i);
        }
    }
    
    result.rmse = std::sqrt(mse / result.length);
    
    float nativeNorm = std::sqrt(nativeNormSq);
    float refNorm = std::sqrt(refNormSq);
    if (nativeNorm > 0 && refNorm > 0) {
        result.cosine = dotProduct / (nativeNorm * refNorm);
    }
    
    // Top-10 overlap
    std::vector<std::pair<float, uint32_t>> nativeTop, refTop;
    nativeTop.reserve(result.length);
    refTop.reserve(result.length);
    
    for (size_t i = 0; i < result.length; ++i) {
        nativeTop.emplace_back(native[i], static_cast<uint32_t>(i));
        refTop.emplace_back(ref[i], static_cast<uint32_t>(i));
    }
    
    std::partial_sort(nativeTop.begin(), nativeTop.begin() + 10, nativeTop.end(),
                      [](const auto& a, const auto& b) { return a.first > b.first; });
    std::partial_sort(refTop.begin(), refTop.begin() + 10, refTop.end(),
                      [](const auto& a, const auto& b) { return a.first > b.first; });
    
    result.top10Overlap = 0;
    for (int i = 0; i < 10; ++i) {
        for (int j = 0; j < 10; ++j) {
            if (nativeTop[i].second == refTop[j].second) {
                result.top10Overlap++;
                break;
            }
        }
    }
    
    return result;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <native_logits.bin> <ref_logits.bin>" << std::endl;
        return 1;
    }
    
    auto result = compareLogits(argv[1], argv[2]);
    
    std::cout << "COMPARISON RESULT" << std::endl;
    std::cout << "=================" << std::endl;
    std::cout << "Length: " << result.length << std::endl;
    std::cout << "All Finite: " << (result.allFinite ? "YES" : "NO") << std::endl;
    std::cout << "Cosine: " << result.cosine << std::endl;
    std::cout << "RMSE: " << result.rmse << std::endl;
    std::cout << "Max Abs Diff: " << result.maxAbsDiff << std::endl;
    std::cout << "Argmax Native: " << result.argmaxNative << std::endl;
    std::cout << "Argmax Reference: " << result.argmaxRef << std::endl;
    std::cout << "Argmax Match: " << (result.argmaxNative == result.argmaxRef ? "YES" : "NO") << std::endl;
    std::cout << "Top-10 Overlap: " << result.top10Overlap << "/10" << std::endl;
    
    return 0;
}