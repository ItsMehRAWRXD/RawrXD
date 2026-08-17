// ============================================================================
// TensorView.hpp
// ============================================================================
// Materializes tensor data from UniversalTensorDescriptor.
// Bridges the gap between descriptor (metadata) and kernel input (bytes).
//
// Key property: zero-copy when resident, lazy-load when streamed.
//
// Copyright (c) 2026 RawrXD Sovereign Runtime
// ============================================================================

#pragma once

#include "UniversalTensorDescriptor.hpp"
#include "KernelRegistry.hpp"
#include <cstdlib>
#include <cstring>
#include <cstdio>

namespace RawrXD {

// ============================================================================
// TensorView - A materialized view of a tensor
// ============================================================================
// This is what kernels actually receive. It wraps:
//   - Raw data pointer (may be memory-mapped, resident, or freshly loaded)
//   - Dequantization scales (if quantized)
//   - Shape/stride info for indexing
// ============================================================================
class TensorView {
public:
    TensorView() : data_(nullptr), scales_(nullptr), zeros_(nullptr),
        desc_(), ownsData_(false) {}

    ~TensorView() {
        if (ownsData_ && data_) {
            _aligned_free(data_);
        }
    }

    // ------------------------------------------------------------------------
    // Construct from a resident descriptor (zero-copy)
    // ------------------------------------------------------------------------
    static TensorView FromResident(const UniversalTensorDescriptor& desc) {
        TensorView view;
        view.desc_ = desc;
        view.data_ = desc.data;
        view.ownsData_ = false;
        return view;
    }

    // ------------------------------------------------------------------------
    // Construct by loading from a file (lazy materialization)
    // ------------------------------------------------------------------------
    static TensorView FromFile(const UniversalTensorDescriptor& desc,
                                const char* filePath,
                                uint64_t fileOffset) {
        TensorView view;
        view.desc_ = desc;

        uint64_t byteSize = desc.byteSize();
        view.data_ = _aligned_malloc(byteSize, 64);
        if (!view.data_) {
            return view;  // Failed
        }
        view.ownsData_ = true;

        // Read from file
        FILE* f = fopen(filePath, "rb");
        if (!f) {
            _aligned_free(view.data_);
            view.data_ = nullptr;
            view.ownsData_ = false;
            return view;
        }
        fseek(f, static_cast<long>(fileOffset), SEEK_SET);
        size_t read = fread(view.data_, 1, byteSize, f);
        fclose(f);

        if (read != byteSize) {
            _aligned_free(view.data_);
            view.data_ = nullptr;
            view.ownsData_ = false;
        }

        return view;
    }

    // ------------------------------------------------------------------------
    // Construct from raw buffer (take ownership)
    // ------------------------------------------------------------------------
    static TensorView FromBuffer(const UniversalTensorDescriptor& desc,
                                   void* buffer,
                                   bool takeOwnership = false) {
        TensorView view;
        view.desc_ = desc;
        view.data_ = buffer;
        view.ownsData_ = takeOwnership;
        return view;
    }

    // ------------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------------
    void* data() const { return data_; }
    const float* asF32() const { return reinterpret_cast<const float*>(data_); }
    const void* raw() const { return data_; }

    const UniversalTensorDescriptor& descriptor() const { return desc_; }
    QuantType quantType() const { return desc_.quantType; }
    TensorLayout layout() const { return desc_.layout; }
    uint64_t numElements() const { return desc_.numElements(); }
    uint64_t byteSize() const { return desc_.byteSize(); }

    // Return shape dimensions as a vector for shape validation
    std::vector<uint64_t> dims() const {
        std::vector<uint64_t> d;
        for (uint8_t i = 0; i < desc_.numDims; ++i) {
            d.push_back(desc_.shape[i]);
        }
        return d;
    }

    // ------------------------------------------------------------------------
    // Block info for quantized tensors
    // ------------------------------------------------------------------------
    uint32_t blockSize() const { return desc_.blockSize; }
    uint32_t blockSizeBytes() const { return desc_.blockSizeBytes; }
    uint64_t numBlocks() const {
        if (desc_.blockSize == 0) return 0;
        return numElements() / desc_.blockSize;
    }

    // ------------------------------------------------------------------------
    // Get scale pointer for a specific block
    // ------------------------------------------------------------------------
    const void* scales() const { return scales_; }
    const void* zeros() const { return zeros_; }

    void setScales(const void* s) { scales_ = s; }
    void setZeros(const void* z) { zeros_ = z; }

    // ------------------------------------------------------------------------
    // Indexing helpers (for dense F32 tensors)
    // ------------------------------------------------------------------------
    float elementAt(uint64_t idx) const {
        if (desc_.quantType == QuantType::F32) {
            return asF32()[idx];
        }
        // For quantized, caller must use kernel
        return 0.0f;
    }

    float elementAt(uint32_t row, uint32_t col) const {
        if (desc_.numDims != 2) return 0.0f;
        return elementAt(row * desc_.shape[1] + col);
    }

    // ------------------------------------------------------------------------
    // Dequantize a single block to F32 (for validation/debugging)
    // ------------------------------------------------------------------------
    void dequantizeBlock(uint64_t blockIdx, float* out) const {
        if (!desc_.isQuantized() || !data_) {
            // Dense - just copy
            uint64_t start = blockIdx * desc_.blockSize;
            for (uint32_t i = 0; i < desc_.blockSize; ++i) {
                out[i] = elementAt(start + i);
            }
            return;
        }

        // Q4_0 dequantization (example - real impl handles all types)
        if (desc_.quantType == QuantType::Q4_0) {
            // Q4_0 block: fp16 scale (2 bytes) + 32 packed nibbles (16 bytes) = 18 bytes
            const uint8_t* blockPtr = reinterpret_cast<const uint8_t*>(data_) +
                                       blockIdx * desc_.blockSizeBytes;

            // Read fp16 scale
            uint16_t scaleBits = *reinterpret_cast<const uint16_t*>(blockPtr);
            float scale = fp16ToF32(scaleBits);

            // Unpack 32 nibbles from 16 bytes
            const uint8_t* weights = blockPtr + 2;
            for (uint32_t i = 0; i < 16; ++i) {
                uint8_t packed = weights[i];
                int8_t w0 = static_cast<int8_t>(packed & 0x0F) - 8;
                int8_t w1 = static_cast<int8_t>((packed >> 4) & 0x0F) - 8;
                out[i * 2]     = scale * static_cast<float>(w0);
                out[i * 2 + 1] = scale * static_cast<float>(w1);
            }
        }
        // Other quant types would be handled by registered dequant kernels
    }

    // ------------------------------------------------------------------------
    // Full dequantization to F32 buffer (for validation)
    // ------------------------------------------------------------------------
    void dequantizeAll(float* out) const {
        if (!desc_.isQuantized()) {
            // Dense - memcpy
            std::memcpy(out, data_, byteSize());
            return;
        }

        uint64_t nBlocks = numBlocks();
        for (uint64_t b = 0; b < nBlocks; ++b) {
            dequantizeBlock(b, out + b * desc_.blockSize);
        }
    }

    // ------------------------------------------------------------------------
    // Validate: check data is not all zeros (basic sanity)
    // ------------------------------------------------------------------------
    bool isValid() const {
        if (!data_) return false;
        if (desc_.quantType == QuantType::F32) {
            const float* f = asF32();
            bool allZero = true;
            uint64_t check = std::min<uint64_t>(numElements(), 256);
            for (uint64_t i = 0; i < check; ++i) {
                if (f[i] != 0.0f) { allZero = false; break; }
            }
            return !allZero;
        }
        return true;  // Can't easily validate quantized
    }

private:
    void* data_;
    const void* scales_;
    const void* zeros_;
    UniversalTensorDescriptor desc_;
    bool ownsData_;

    // fp16 -> fp32 conversion
    static float fp16ToF32(uint16_t h) {
        uint32_t sign = (h >> 15) & 1;
        uint32_t exp = (h >> 10) & 0x1F;
        uint32_t mant = h & 0x3FF;

        if (exp == 0) {
            if (mant == 0) {
                uint32_t f = sign << 31;
                float result;
                std::memcpy(&result, &f, 4);
                return result;
            }
            // Denormal - normalize
            while ((mant & 0x400) == 0) {
                mant <<= 1;
                exp--;
            }
            exp++;
            mant &= 0x3FF;
        } else if (exp == 0x1F) {
            uint32_t f = (sign << 31) | (0xFF << 23) | (mant << 13);
            float result;
            std::memcpy(&result, &f, 4);
            return result;
        }

        uint32_t f = (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13);
        float result;
        std::memcpy(&result, &f, 4);
        return result;
    }
};

// ============================================================================
// TensorDatabase - Collection of materialized tensor views
// ============================================================================
class TensorDatabase {
public:
    void add(const std::string& name, TensorView view) {
        tensors_[name] = std::move(view);
    }

    TensorView* find(const std::string& name) {
        auto it = tensors_.find(name);
        if (it != tensors_.end()) return &it->second;
        return nullptr;
    }

    const TensorView* find(const std::string& name) const {
        auto it = tensors_.find(name);
        if (it != tensors_.end()) return &it->second;
        return nullptr;
    }

    size_t size() const { return tensors_.size(); }

private:
    std::unordered_map<std::string, TensorView> tensors_;
};

} // namespace RawrXD
