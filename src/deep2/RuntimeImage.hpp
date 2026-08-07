// ============================================================================
// RuntimeImage.hpp
// ============================================================================
// The compiled, in-memory representation of a model ready for execution.
// This is the "machine code equivalent for neural networks" - all parsing,
// kernel resolution, graph construction, and memory planning are done ONCE.
//
// The .rxd file is a serialized snapshot of this structure.
//
// Copyright (c) 2026 RawrXD Sovereign Runtime
// ============================================================================

#pragma once

#include "UniversalTensorDescriptor.hpp"
#include "KernelRegistry.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>

namespace RawrXD {

// ============================================================================
// RXD File Header (on-disk format)
// ============================================================================
#pragma pack(push, 1)
struct RXDHeader {
    char     magic[4];          // "RXD\0"
    uint32_t version;           // Format version
    uint32_t targetISA;         // ISATarget enum value
    uint32_t backend;            // 0=CPU, 1=GPU, 2=Hybrid
    uint64_t graphHash;          // Hash of execution graph (for cache validation)
    uint64_t creationTime;       // Unix timestamp
    uint32_t numLayers;          // Number of transformer layers
    uint32_t numTensors;         // Number of tensors in manifest
    uint32_t numKernels;         // Number of resolved kernel entries
    uint32_t numMemoryRegions;   // Number of memory regions
    uint32_t headerSize;         // Size of this header
    uint64_t graphOffset;        // Offset to execution graph
    uint64_t tensorManifestOffset; // Offset to tensor manifest
    uint64_t kernelTableOffset;  // Offset to kernel table
    uint64_t memoryLayoutOffset; // Offset to memory layout
    uint64_t tensorDataOffset;   // Offset to raw tensor data
    uint64_t tensorDataSize;     // Total tensor data size
    char     modelName[64];      // Model name (null-terminated)
    char     architecture[32];   // Architecture string
};
#pragma pack(pop)

// ============================================================================
// Serialized Tensor Manifest Entry
// ============================================================================
#pragma pack(push, 1)
struct RXDTensorEntry {
    char     name[64];           // Tensor name
    uint8_t  numDims;            // Number of dimensions
    uint64_t shape[8];           // Shape
    uint16_t quantType;          // QuantType enum
    uint8_t  layout;             // TensorLayout enum
    uint8_t  role;               // TensorRole enum
    uint32_t blockSize;          // Block size (for quantized)
    uint32_t blockSizeBytes;     // Block size in bytes
    uint8_t  memorySpace;        // MemorySpace enum
    uint64_t dataOffset;         // Offset within tensor data section
    uint64_t byteSize;           // Size in bytes
    uint32_t layerIdx;           // Which layer (0xFFFF = global)
};
#pragma pack(pop)

// ============================================================================
// Serialized Kernel Table Entry
// ============================================================================
#pragma pack(push, 1)
struct RXDKernelEntry {
    uint8_t  kernelType;         // KernelType enum
    uint16_t quantType;          // QuantType this kernel handles
    uint8_t  isaTarget;          // ISATarget enum
    uint32_t kernelId;           // Index into kernel registry (resolved at load)
    char     kernelName[64];     // Symbol name for late binding
};
#pragma pack(pop)

// ============================================================================
// Serialized Memory Region
// ============================================================================
#pragma pack(push, 1)
struct RXDMemoryRegion {
    uint64_t virtualAddress;     // Virtual address in RXD address space
    uint64_t size;                // Region size in bytes
    uint8_t  type;                // 0=weights, 1=KVCache, 2=expert, 3=activation
    uint8_t  residency;          // 0=resident, 1=streamed, 2=NVMe-paged
    uint32_t flags;              // Region flags
};
#pragma pack(pop)

// ============================================================================
// Serialized Execution Graph Node
// ============================================================================
#pragma pack(push, 1)
struct RXDGraphNode {
    uint8_t  opType;             // ExecOpType (RMSNorm, QKV, Attention, MoE, etc.)
    uint32_t layerIdx;           // Layer index
    uint32_t inputTensorId;      // Index into tensor manifest
    uint32_t outputTensorId;     // Index into tensor manifest
    uint32_t weightTensorId;     // Weight tensor index
    uint32_t kernelEntryId;      // Index into kernel table
    uint32_t expertIndices[8];   // For MoE: selected experts
    uint8_t  numExperts;         // Number of experts (0 = not MoE)
    uint32_t deps[4];            // Dependency node indices
    uint8_t  numDeps;            // Number of dependencies
};
#pragma pack(pop)

// ============================================================================
// Runtime Image (in-memory, after loading .rxd)
// ============================================================================
struct RuntimeImage {
    // Metadata
    std::string modelName;
    std::string architecture;
    ISATarget   targetISA;
    uint64_t    graphHash;
    uint64_t    creationTime;

    // Tensor manifest
    std::vector<RXDTensorEntry> tensors;

    // Kernel table (resolved at load time via late binding)
    std::vector<RXDKernelEntry> kernels;

    // Memory regions
    std::vector<RXDMemoryRegion> memoryRegions;

    // Execution graph
    std::vector<RXDGraphNode> graph;

    // Raw tensor data (memory-mapped from .rxd file)
    void*     tensorData;
    uint64_t  tensorDataSize;
    bool      ownsData;

    // Resolved kernel function pointers (filled at load)
    ResolvedKernelTable resolvedKernels;

    RuntimeImage() : targetISA(ISATarget::SCALAR), graphHash(0),
        creationTime(0), tensorData(nullptr), tensorDataSize(0), ownsData(false) {}

    ~RuntimeImage() {
        if (ownsData && tensorData) {
            free(tensorData);
        }
    }

    // Check if this image is valid for current hardware
    bool isValidForHardware() const {
        ISATarget current = KernelRegistry::DetectBestISA();
        // Image must target an ISA <= current (or equal for optimal)
        return static_cast<uint8_t>(targetISA) <= static_cast<uint8_t>(current);
    }

    // Get tensor data pointer by manifest index
    void* getTensorData(uint32_t tensorIdx) const {
        if (tensorIdx >= tensors.size()) return nullptr;
        return static_cast<char*>(tensorData) + tensors[tensorIdx].dataOffset;
    }

    // Find tensor by name
    const RXDTensorEntry* findTensor(const std::string& name) const {
        for (const auto& t : tensors) {
            if (name == t.name) return &t;
        }
        return nullptr;
    }

    // Execute next token (the hot path - no parsing, no resolution)
    // This is what the runtime calls in the generation loop
    bool executeNextToken(const float* input, float* output, uint32_t position);
};

// ============================================================================
// RXD Compiler - Takes a model and compiles to RuntimeImage
// ============================================================================
class RXDCompiler {
public:
    // Compile from a loaded model (any format)
    static std::unique_ptr<RuntimeImage> Compile(
        const ModelMetadata& metadata,
        const std::vector<TensorEntry>& tensorCatalog,
        const ResolvedKernelTable& kernels,
        ISATarget targetISA
    );

    // Serialize RuntimeImage to .rxd file
    static bool Serialize(const RuntimeImage& image, const std::string& outputPath);

    // Deserialize .rxd file to RuntimeImage (with late kernel binding)
    static std::unique_ptr<RuntimeImage> Deserialize(const std::string& inputPath);

    // Compute graph hash (for cache validation)
    static uint64_t ComputeGraphHash(const std::vector<RXDGraphNode>& graph);

    // Check if .rxd is up to date (hash matches model)
    static bool IsCacheValid(const std::string& rxdPath, uint64_t expectedHash);
};

} // namespace RawrXD
