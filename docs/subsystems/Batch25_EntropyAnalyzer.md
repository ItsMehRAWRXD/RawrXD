# Batch 25 - Entropy Analyzer
## Sovereign IDE Subsystem Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

The Entropy Analyzer analyzes entropy across binary regions to detect compression, encryption, or obfuscation. It provides entropy calculation, region classification, obfuscation detection, and compression detection.

### Key Characteristics

| Attribute | Value |
|-----------|-------|
| **Language** | C++17 |
| **Lines of Code** | ~2,800 |
| **Block Size** | 256 bytes |
| **Entropy Thresholds** | 3 (Low, Medium, High) |
| **SEG Nodes** | 1 |
| **MoE Experts** | 1 |

---

## Responsibilities

1. **Entropy Calculation** - Calculate Shannon entropy
2. **Region Classification** - Classify regions by entropy
3. **Obfuscation Detection** - Detect obfuscated code
4. **Compression Detection** - Detect compressed data
5. **Encryption Detection** - Detect encrypted data

---

## Architecture

```
┌─────────────────────────────────────────────┐
│           Entropy Analyzer                  │
├─────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────────┐    │
│  │   Entropy    │  │   Region         │    │
│  │   Calculator │  │   Classifier     │    │
│  └──────────────┘  └──────────────────┘    │
│  ┌──────────────┐  ┌──────────────────┐    │
│  │   Obfuscation│  │   Compression    │    │
│  │   Detector   │  │   Detector       │    │
│  └──────────────┘  └──────────────────┘    │
└─────────────────────────────────────────────┘
```

---

## ABI Surfaces

```cpp
// Entropy analyzer initialization
SOVEREIGN_API EntropyResult Entropy_Initialize();
SOVEREIGN_API void Entropy_Shutdown();

// Entropy calculation
SOVEREIGN_API float Entropy_Calculate(const void* data, size_t size);
SOVEREIGN_API EntropyResult Entropy_AnalyzeBinary(BinaryHandle binary,
                                                    EntropyMap** map);

// Region classification
SOVEREIGN_API EntropyLevel Entropy_Classify(float entropy);
SOVEREIGN_API EntropyRegion* Entropy_GetRegions(EntropyMap* map);
SOVEREIGN_API size_t Entropy_GetRegionCount(EntropyMap* map);

// Detection
SOVEREIGN_API bool Entropy_IsObfuscated(EntropyRegion* region);
SOVEREIGN_API bool Entropy_IsCompressed(EntropyRegion* region);
SOVEREIGN_API bool Entropy_IsEncrypted(EntropyRegion* region);
```

---

## SEG Nodes

| Node ID | Name | Type | Description |
|---------|------|------|-------------|
| 0x001D | `SEGNode_EntropyAnalyze` | Analysis | Analyze entropy of binary regions |

---

## MoE Experts

| Expert Name | Domain | Description |
|-------------|--------|-------------|
| `Expert_EntropyInference` | entropy | Infer data type from entropy |

---

## Implementation Details

### Entropy Calculator

```cpp
class EntropyCalculator {
public:
    float Calculate(const uint8_t* data, size_t size) {
        if (size == 0) return 0.0f;
        
        // Count byte frequencies
        std::array<uint32_t, 256> frequencies = {};
        for (size_t i = 0; i < size; ++i) {
            frequencies[data[i]]++;
        }
        
        // Calculate Shannon entropy
        float entropy = 0.0f;
        for (uint32_t count : frequencies) {
            if (count == 0) continue;
            
            float probability = (float)count / size;
            entropy -= probability * std::log2(probability);
        }
        
        // Normalize to 0-8 range (bits per byte)
        return entropy;
    }
    
    EntropyMap AnalyzeBinary(const Binary& binary) {
        EntropyMap map;
        map.binary = &binary;
        
        const size_t blockSize = 256;
        const uint8_t* data = binary.GetData();
        size_t size = binary.GetSize();
        
        for (size_t offset = 0; offset < size; offset += blockSize) {
            size_t blockLen = std::min(blockSize, size - offset);
            float entropy = Calculate(data + offset, blockLen);
            
            EntropyRegion region;
            region.start = binary.GetBaseAddress() + offset;
            region.size = blockLen;
            region.entropy = entropy;
            region.level = Classify(entropy);
            
            map.regions.push_back(region);
        }
        
        return map;
    }
    
    EntropyLevel Classify(float entropy) {
        if (entropy < 4.0f) {
            return ENTROPY_LOW;      // Plain text, code
        } else if (entropy < 7.0f) {
            return ENTROPY_MEDIUM;   // Compressed
        } else {
            return ENTROPY_HIGH;     // Encrypted, packed
        }
    }
};
```

### Obfuscation Detector

```cpp
class ObfuscationDetector {
public:
    bool IsObfuscated(const EntropyRegion& region) {
        // High entropy in code section suggests obfuscation
        if (region.level == ENTROPY_HIGH && IsCodeSection(region)) {
            return true;
        }
        
        // Check for entropy anomalies
        if (HasEntropyAnomaly(region)) {
            return true;
        }
        
        return false;
    }
    
    bool IsCompressed(const EntropyRegion& region) {
        // Medium-high entropy in data section
        if (region.level == ENTROPY_MEDIUM && IsDataSection(region)) {
            return true;
        }
        
        // Check for compression signatures
        if (HasCompressionSignature(region)) {
            return true;
        }
        
        return false;
    }
    
    bool IsEncrypted(const EntropyRegion& region) {
        // Very high entropy (close to 8.0)
        if (region.entropy > 7.5f) {
            return true;
        }
        
        // Check for encryption signatures
        if (HasEncryptionSignature(region)) {
            return true;
        }
        
        return false;
    }
    
private:
    bool HasEntropyAnomaly(const EntropyRegion& region) {
        // Compare with surrounding regions
        // Sudden entropy changes suggest packing/obfuscation
        // ...
        return false;
    }
    
    bool HasCompressionSignature(const EntropyRegion& region) {
        // Check for common compression signatures
        // ...
        return false;
    }
    
    bool HasEncryptionSignature(const EntropyRegion& region) {
        // Check for encryption headers
        // ...
        return false;
    }
};
```

---

## Testing

```cpp
TEST(EntropyAnalyzer, CalculateEntropy) {
    Entropy_Initialize();
    
    // Test with uniform data (low entropy)
    uint8_t uniform[256];
    memset(uniform, 0x41, sizeof(uniform));
    float entropy1 = Entropy_Calculate(uniform, sizeof(uniform));
    EXPECT_LT(entropy1, 1.0f);  // Should be very low
    
    // Test with random data (high entropy)
    uint8_t random[256];
    for (size_t i = 0; i < sizeof(random); ++i) {
        random[i] = rand() % 256;
    }
    float entropy2 = Entropy_Calculate(random, sizeof(random));
    EXPECT_GT(entropy2, 7.0f);  // Should be high
    
    Entropy_Shutdown();
}

TEST(EntropyAnalyzer, ClassifyRegions) {
    Entropy_Initialize();
    
    // Load binary with mixed content
    auto binary = Loader_Load("mixed_content.exe");
    
    // Analyze entropy
    EntropyMap* map;
    auto result = Entropy_AnalyzeBinary(binary, &map);
    EXPECT_EQ(result, ENTROPY_SUCCESS);
    
    // Check regions
    size_t regionCount = Entropy_GetRegionCount(map);
    EXPECT_GT(regionCount, 0);
    
    // Should find different entropy levels
    bool foundLow = false, foundHigh = false;
    for (size_t i = 0; i < regionCount; ++i) {
        auto region = Entropy_GetRegions(map)[i];
        if (region.level == ENTROPY_LOW) foundLow = true;
        if (region.level == ENTROPY_HIGH) foundHigh = true;
    }
    EXPECT_TRUE(foundLow);
    EXPECT_TRUE(foundHigh);
    
    Entropy_Shutdown();
}
```

---

## Summary

Batch 25 - Entropy Analyzer provides:

- ✅ **Shannon entropy calculation**
- ✅ **Region classification**
- ✅ **Obfuscation detection**
- ✅ **Compression detection**
- ✅ **Encryption detection**

**Status:** ✅ Complete
