//============================================================================
// nevm_nano_format.cpp
// RawrXD .nano Container Format - Implementation
//============================================================================

#include "nevm_nano_format.hpp"
#include <algorithm>
#include <cstring>
#include <lz4.h>
#include <zstd.h>

namespace RawrXD {
namespace NEVM {

//============================================================================
// NanoContainer Implementation
//============================================================================

NanoContainer::NanoContainer() : cache_valid_(false) {
    std::memset(&header_, 0, sizeof(header_));
}

NanoContainer::~NanoContainer() {
    Close();
}

bool NanoContainer::Open(const std::wstring& path) {
    Close();
    
    file_.open(path, std::ios::binary | std::ios::in);
    if (!file_.is_open()) {
        return false;
    }
    
    if (!ReadHeader()) {
        Close();
        return false;
    }
    
    if (!header_.Validate()) {
        Close();
        return false;
    }
    
    return true;
}

bool NanoContainer::Create(const std::wstring& path, const NanoHeader& header) {
    Close();
    
    file_.open(path, std::ios::binary | std::ios::out | std::ios::trunc);
    if (!file_.is_open()) {
        return false;
    }
    
    header_ = header;
    std::memcpy(header_.magic, NANO_MAGIC, 8);
    header_.version = NANO_VERSION;
    
    if (!WriteHeader(header_)) {
        Close();
        return false;
    }
    
    return true;
}

void NanoContainer::Close() {
    if (file_.is_open()) {
        file_.close();
    }
    InvalidateCache();
    std::memset(&header_, 0, sizeof(header_));
}

bool NanoContainer::ReadHeader() {
    file_.seekg(0, std::ios::beg);
    file_.read(reinterpret_cast<char*>(&header_), sizeof(header_));
    return file_.good();
}

bool NanoContainer::WriteHeader(const NanoHeader& header) {
    file_.seekp(0, std::ios::beg);
    file_.write(reinterpret_cast<const char*>(&header), sizeof(header));
    return file_.good();
}

bool NanoContainer::ReadLayerDesc(uint32_t layer_id, NanoLayerDesc& desc) {
    if (!file_.is_open()) return false;
    
    // Calculate offset: header + layer_id * sizeof(desc)
    uint64_t offset = header_.layer_table_offset + layer_id * sizeof(NanoLayerDesc);
    file_.seekg(offset, std::ios::beg);
    file_.read(reinterpret_cast<char*>(&desc), sizeof(desc));
    
    return file_.good() && desc.layer_id == layer_id;
}

bool NanoContainer::WriteLayerDesc(const NanoLayerDesc& desc) {
    if (!file_.is_open()) return false;
    
    uint64_t offset = header_.layer_table_offset + desc.layer_id * sizeof(NanoLayerDesc);
    file_.seekp(offset, std::ios::beg);
    file_.write(reinterpret_cast<const char*>(&desc), sizeof(desc));
    
    InvalidateCache();
    return file_.good();
}

bool NanoContainer::ReadTensorEntry(const std::string& name, NanoTensorEntry& entry) {
    if (!file_.is_open()) return false;
    
    // Load cache if needed
    if (!cache_valid_ && !LoadCache()) {
        return false;
    }
    
    // Search in cache
    for (const auto& e : tensor_cache_) {
        if (name == e.name) {
            entry = e;
            return true;
        }
    }
    
    return false;
}

bool NanoContainer::WriteTensorEntry(const NanoTensorEntry& entry) {
    if (!file_.is_open()) return false;
    
    // Find next available slot
    uint64_t offset = header_.tensor_dir_offset + 
                      tensor_cache_.size() * sizeof(NanoTensorEntry);
    
    file_.seekp(offset, std::ios::beg);
    file_.write(reinterpret_cast<const char*>(&entry), sizeof(entry));
    
    InvalidateCache();
    return file_.good();
}

bool NanoContainer::ReadTensorData(const NanoTensorEntry& entry, void* buffer, 
                                     size_t buffer_size) {
    if (!file_.is_open() || !buffer) return false;
    
    if (buffer_size < entry.uncompressed_size) {
        return false;
    }
    
    // Seek to data
    file_.seekg(entry.data_offset, std::ios::beg);
    
    // Read compressed data
    std::vector<uint8_t> compressed(entry.compressed_size);
    file_.read(reinterpret_cast<char*>(compressed.data()), entry.compressed_size);
    
    if (!file_.good()) {
        return false;
    }
    
    // Decompress based on format
    switch (entry.format) {
        case NANO_COMP_NONE:
            std::memcpy(buffer, compressed.data(), entry.compressed_size);
            return true;
            
        case NANO_COMP_LZ4:
            {
                int result = LZ4_decompress_safe(
                    reinterpret_cast<const char*>(compressed.data()),
                    static_cast<char*>(buffer),
                    static_cast<int>(entry.compressed_size),
                    static_cast<int>(entry.uncompressed_size)
                );
                return result > 0;
            }
            
        case NANO_COMP_ZSTD:
            {
                size_t result = ZSTD_decompress(
                    buffer, entry.uncompressed_size,
                    compressed.data(), entry.compressed_size
                );
                return !ZSTD_isError(result);
            }
            
        default:
            return false;
    }
}

bool NanoContainer::WriteTensorData(const NanoTensorEntry& entry, const void* data, 
                                     size_t size) {
    if (!file_.is_open() || !data) return false;
    
    // Seek to data offset
    file_.seekp(entry.data_offset, std::ios::beg);
    file_.write(static_cast<const char*>(data), size);
    
    return file_.good();
}

bool NanoContainer::LoadCache() {
    if (!file_.is_open()) return false;
    
    layer_cache_.clear();
    tensor_cache_.clear();
    
    // Load layers
    for (uint32_t i = 0; i < header_.num_layers; ++i) {
        NanoLayerDesc desc;
        if (ReadLayerDesc(i, desc)) {
            layer_cache_.push_back(desc);
        }
    }
    
    // Load tensor directory
    file_.seekg(header_.tensor_dir_offset, std::ios::beg);
    for (uint32_t i = 0; i < header_.num_tensors; ++i) {
        NanoTensorEntry entry;
        file_.read(reinterpret_cast<char*>(&entry), sizeof(entry));
        if (file_.good()) {
            tensor_cache_.push_back(entry);
        }
    }
    
    cache_valid_ = true;
    return true;
}

void NanoContainer::InvalidateCache() {
    layer_cache_.clear();
    tensor_cache_.clear();
    cache_valid_ = false;
}

uint64_t NanoContainer::AlignOffset(uint64_t offset, uint64_t alignment) {
    return (offset + alignment - 1) & ~(alignment - 1);
}

bool NanoContainer::ValidateContainer() {
    if (!file_.is_open()) return false;
    
    // Check magic
    if (!header_.Validate()) {
        return false;
    }
    
    // Check version compatibility
    if (header_.version > NANO_VERSION) {
        return false;
    }
    
    // Check file size
    file_.seekg(0, std::ios::end);
    uint64_t actual_size = file_.tellg();
    if (actual_size < header_.total_size) {
        return false;
    }
    
    // Validate all layers
    for (uint32_t i = 0; i < header_.num_layers; ++i) {
        if (!ValidateLayer(i)) {
            return false;
        }
    }
    
    return true;
}

bool NanoContainer::ValidateLayer(uint32_t layer_id) {
    NanoLayerDesc desc;
    if (!ReadLayerDesc(layer_id, desc)) {
        return false;
    }
    
    // Check layer type
    if (desc.layer_type > NANO_LAYER_IMPORTANCE) {
        return false;
    }
    
    // Check bit allocation
    if (desc.base_bits != 1 && desc.base_bits != 2 && desc.base_bits != 4) {
        return false;
    }
    
    // Check offsets are within bounds
    if (desc.weights_offset > header_.total_size ||
        desc.codebook_offset > header_.total_size) {
        return false;
    }
    
    return true;
}

NanoContainer::Stats NanoContainer::ComputeStats() const {
    Stats stats = {};
    
    if (!file_.is_open()) return stats;
    
    stats.compressed_size = header_.compressed_size;
    stats.compression_ratio = header_.compression_ratio;
    stats.avg_bits_per_param = header_.avg_bits_per_param;
    stats.layer_count = header_.num_layers;
    stats.tensor_count = header_.num_tensors;
    
    // Count total parameters
    for (const auto& layer : layer_cache_) {
        stats.total_params += layer.num_params;
    }
    
    return stats;
}

//============================================================================
// NanoQuantizer Implementation
//============================================================================

NanoQuantizer::NanoQuantizer(const Config& config) : config_(config) {}

bool NanoQuantizer::Quantize(const float* input, uint64_t count,
                               uint8_t* base_quantized, uint8_t* residual_quantized,
                               uint32_t* residual_indices, uint64_t& residual_count,
                               float* codebook, uint32_t& codebook_entries) {
    if (!input || !base_quantized) return false;
    
    // Compute codebook
    codebook_entries = 1u << config_.base_bits;  // 2, 4, 16, or 256 entries
    if (!ComputeCodebook(input, count, codebook_entries, codebook)) {
        return false;
    }
    
    // Quantize to base layer
    for (uint64_t i = 0; i < count; ++i) {
        // Find nearest codebook entry
        float min_dist = std::abs(input[i] - codebook[0]);
        uint32_t best_idx = 0;
        
        for (uint32_t j = 1; j < codebook_entries; ++j) {
            float dist = std::abs(input[i] - codebook[j]);
            if (dist < min_dist) {
                min_dist = dist;
                best_idx = j;
            }
        }
        
        // Pack indices based on bit width
        if (config_.base_bits == 1) {
            // 1 bit: 8 indices per byte
            uint64_t byte_idx = i / 8;
            uint32_t bit_idx = i % 8;
            base_quantized[byte_idx] |= (best_idx & 1) << bit_idx;
        } else if (config_.base_bits == 2) {
            // 2 bits: 4 indices per byte
            uint64_t byte_idx = i / 4;
            uint32_t shift = (i % 4) * 2;
            base_quantized[byte_idx] |= (best_idx & 3) << shift;
        } else if (config_.base_bits == 4) {
            // 4 bits: 2 indices per byte
            uint64_t byte_idx = i / 2;
            uint32_t shift = (i % 2) * 4;
            base_quantized[byte_idx] |= (best_idx & 15) << shift;
        }
    }
    
    // Compute residuals if requested
    if (config_.residual_bits > 0 && residual_quantized) {
        std::vector<float> residuals;
        std::vector<uint32_t> indices;
        
        // Reconstruct base
        std::vector<float> reconstructed(count);
        for (uint64_t i = 0; i < count; ++i) {
            uint32_t idx;
            if (config_.base_bits == 1) {
                idx = (base_quantized[i / 8] >> (i % 8)) & 1;
            } else if (config_.base_bits == 2) {
                idx = (base_quantized[i / 4] >> ((i % 4) * 2)) & 3;
            } else {
                idx = (base_quantized[i / 2] >> ((i % 2) * 4)) & 15;
            }
            reconstructed[i] = codebook[idx];
        }
        
        // Compute residuals
        float threshold = 0.0f;  // Include all for now
        ComputeResiduals(input, reconstructed.data(), count, threshold,
                         residuals, indices);
        
        // Quantize residuals
        residual_count = std::min(residuals.size(), 
                                   static_cast<size_t>(count * config_.residual_sparsity / 100));
        
        for (uint64_t i = 0; i < residual_count; ++i) {
            residual_indices[i] = indices[i];
            // Quantize residual value
            float r = residuals[i];
            // Simple linear quantization
            int32_t q = static_cast<int32_t>(r * 127.0f);
            q = std::max(-128, std::min(127, q));
            residual_quantized[i] = static_cast<uint8_t>(q + 128);
        }
    } else {
        residual_count = 0;
    }
    
    return true;
}

bool NanoQuantizer::ComputeCodebook(const float* data, uint64_t count,
                                     uint32_t entries, float* codebook) {
    if (!data || !codebook || entries == 0) return false;
    
    if (entries == 2) {
        // Binary: just min/max
        float min_val = data[0], max_val = data[0];
        for (uint64_t i = 1; i < count; ++i) {
            min_val = std::min(min_val, data[i]);
            max_val = std::max(max_val, data[i]);
        }
        codebook[0] = min_val;
        codebook[1] = max_val;
    } else if (entries == 4) {
        // 2-bit: use k-means with 4 centroids
        KMeansCluster(data, count, 4, codebook);
    } else {
        // More entries: k-means
        KMeansCluster(data, count, entries, codebook);
    }
    
    return true;
}

bool NanoQuantizer::KMeansCluster(const float* data, uint64_t count,
                                     uint32_t k, float* centroids) {
    if (!data || !centroids || k == 0 || count == 0) return false;
    
    // Initialize centroids evenly spaced
    float min_val = data[0], max_val = data[0];
    for (uint64_t i = 1; i < count; ++i) {
        min_val = std::min(min_val, data[i]);
        max_val = std::max(max_val, data[i]);
    }
    
    for (uint32_t i = 0; i < k; ++i) {
        centroids[i] = min_val + (max_val - min_val) * i / (k - 1);
    }
    
    // K-means iterations
    std::vector<uint32_t> assignments(count);
    std::vector<float> new_centroids(k);
    std::vector<uint32_t> counts(k);
    
    for (int iter = 0; iter < 20; ++iter) {
        // Assign points to nearest centroid
        for (uint64_t i = 0; i < count; ++i) {
            float min_dist = std::abs(data[i] - centroids[0]);
            uint32_t best = 0;
            for (uint32_t j = 1; j < k; ++j) {
                float dist = std::abs(data[i] - centroids[j]);
                if (dist < min_dist) {
                    min_dist = dist;
                    best = j;
                }
            }
            assignments[i] = best;
        }
        
        // Update centroids
        std::fill(new_centroids.begin(), new_centroids.end(), 0.0f);
        std::fill(counts.begin(), counts.end(), 0);
        
        for (uint64_t i = 0; i < count; ++i) {
            new_centroids[assignments[i]] += data[i];
            counts[assignments[i]]++;
        }
        
        for (uint32_t j = 0; j < k; ++j) {
            if (counts[j] > 0) {
                centroids[j] = new_centroids[j] / counts[j];
            }
        }
    }
    
    return true;
}

bool NanoQuantizer::ComputeResiduals(const float* original, const float* reconstructed,
                                      uint64_t count, float threshold,
                                      std::vector<float>& residuals,
                                      std::vector<uint32_t>& indices) {
    residuals.clear();
    indices.clear();
    
    for (uint64_t i = 0; i < count; ++i) {
        float diff = original[i] - reconstructed[i];
        if (std::abs(diff) > threshold) {
            residuals.push_back(diff);
            indices.push_back(static_cast<uint32_t>(i));
        }
    }
    
    return true;
}

//============================================================================
// C API Implementation
//============================================================================

extern "C" {

NanoContainer* NANO_Create() {
    return new NanoContainer();
}

void NANO_Destroy(NanoContainer* container) {
    delete container;
}

int NANO_Open(NanoContainer* container, const wchar_t* path) {
    if (!container || !path) return -1;
    return container->Open(path) ? 0 : -1;
}

int NANO_ReadTensor(NanoContainer* container, const char* name,
                     void* buffer, size_t buffer_size) {
    if (!container || !name || !buffer) return -1;
    
    NanoTensorEntry entry;
    if (!container->ReadTensorEntry(name, entry)) {
        return -1;
    }
    
    return container->ReadTensorData(entry, buffer, buffer_size) ? 0 : -1;
}

int NANO_GetTensorInfo(NanoContainer* container, const char* name,
                        NanoTensorEntry* entry) {
    if (!container || !name || !entry) return -1;
    return container->ReadTensorEntry(name, *entry) ? 0 : -1;
}

} // extern "C"

} // namespace NEVM
} // namespace RawrXD
