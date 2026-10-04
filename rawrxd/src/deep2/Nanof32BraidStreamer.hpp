#pragma once
// ============================================================================
// Nanof32BraidStreamer.hpp — Reverse-streaming loader for nanof32braidQuantless
// ============================================================================
// Reads tensor footers FIRST (backward from EOF), then raw data.
// Decompresses 1.15-bit braid → bfloat16 on demand.
// ============================================================================

#include "Nanof32BraidFormat.hpp"
#include "BP16Streamer.hpp"  // reuses bfloat16_t
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <fstream>

namespace Deep2 {

// ----------------------------------------------------------------------------
// Forward declarations
// ----------------------------------------------------------------------------
struct WeightTensor;

// ----------------------------------------------------------------------------
// Cached tensor block
// ----------------------------------------------------------------------------
struct NQBraidBlock {
    std::string name;             // tensor name from footer
    uint64_t fileOffset = 0;
    size_t   byteCount = 0;
    std::vector<bfloat16_t> bf16Data;  // decompressed output
    bool     ready = false;
};

// ----------------------------------------------------------------------------
// Reverse streamer — reads backward, decompresses to BF16
// ----------------------------------------------------------------------------
class Nanof32BraidStreamer {
public:
    Nanof32BraidStreamer() = default;
    ~Nanof32BraidStreamer();

    // Open model file and validate header
    bool open(const std::string& path);
    void close();
    bool isOpen() const { return file_.is_open(); }

    // Read next tensor footer from EOF backward, then its data
    // Returns false when no more tensors (readHead <= header size)
    bool readNextTensor(Nanof32BraidTensorFooter& outFooter,
                        std::vector<bfloat16_t>& outData);

    // Seek to a specific tensor by index (0 = first tensor in file)
    bool seekTensor(uint32_t index);

    // Direct load: given a tensor name pattern, decompress and return BF16
    // For Deep2Engine integration
    const bfloat16_t* loadTensor(const std::string& namePattern,
                                 size_t& outElements);

    // Release cached tensor
    bool releaseTensor(uint32_t tensorIndex);

    // Stats
    uint64_t bytesReadFromDisk() const { return bytesRead_; }
    uint64_t tensorsLoaded()   const { return tensorsLoaded_; }

    // Header access
    const Nanof32BraidHeader* header() const { return header_.get(); }

    // Architecture metadata (at byte 64, after header)
    bool readArchMeta(Nanof32BraidArchMeta& outMeta);

    // Read all tensors into memory (for model load)
    bool readAllTensors(std::vector<std::pair<std::string, NQBraidBlock>>& outTensors);

    // RAWRXD_BRAID_BLOCK_OWNERSHIP_001
    //
    // The engine's loader binds WeightTensor::data straight into a block's
    // bfloat16 buffer and then returns. Those buffers must therefore outlive
    // the loading function, or every bound WeightTensor dangles. The engine
    // parks the blocks here for exactly that reason.
    std::mutex& cacheMutex() noexcept { return cacheMtx_; }
    std::unordered_map<uint32_t, NQBraidBlock>& cache() noexcept { return cache_; }

private:
    std::ifstream file_;
    std::unique_ptr<Nanof32BraidHeader> header_;
    uint64_t readHead_ = 0;           // current backward offset
    uint64_t bytesRead_ = 0;
    uint64_t tensorsLoaded_ = 0;

    mutable std::mutex cacheMtx_;
    std::unordered_map<uint32_t, NQBraidBlock> cache_;

    // Decompress 1.15-bit braid to BF16 (23 bits per 20 weights)
    bool decompressBraid(const uint8_t* compressed, size_t compBytes,
                         bfloat16_t* output, size_t elements,
                         float scaleMin, float scaleMax);

    // Decompress codebook-quantized to BF16
    bool decompressCodebook(const uint8_t* compressed, size_t compBytes,
                            uint32_t bits, bfloat16_t* output, size_t elements,
                            float scaleMin, float scaleMax);

    // Read raw bytes from file at absolute offset
    bool readAt(uint64_t offset, void* buffer, size_t bytes);
};

} // namespace Deep2
