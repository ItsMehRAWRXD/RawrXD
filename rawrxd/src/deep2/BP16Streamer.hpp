#pragma once
// ============================================================================
// BP16Streamer — Real block/weight streaming with bfloat16 conversion/transport
// Wired to runtime; actual block queue, offset validation, conversion counters.
// ============================================================================
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace Deep2 {

// Lightweight BFloat16 type
struct bfloat16_t {
    uint16_t v = 0;
    bfloat16_t() = default;
    explicit bfloat16_t(uint16_t raw) : v(raw) {}
    explicit bfloat16_t(float f) {
        uint32_t u;
        std::memcpy(&u, &f, sizeof(f));
        v = static_cast<uint16_t>(u >> 16);
    }
    float toFloat() const {
        uint32_t u = static_cast<uint32_t>(v) << 16;
        float f;
        std::memcpy(&f, &u, sizeof(f));
        return f;
    }
};

enum class BP16BlockState : uint8_t {
    Idle = 0,
    Loading,
    Ready,
    Failed
};

struct BP16Block {
    uint64_t blockId = 0;
    uint64_t fileOffset = 0;
    size_t byteCount = 0;
    BP16BlockState state = BP16BlockState::Idle;
    std::vector<bfloat16_t> b16Data;
    int errorCode = 0;
};

struct BP16StreamerConfig {
    size_t blockSize = 4096;
    size_t maxBlocks = 256;
    bool keepHostCopy = true; // keep converted BFloat16 in host memory
};

struct BP16StreamerStats {
    uint64_t blocksRequested = 0;
    uint64_t blocksLoaded = 0;
    uint64_t blocksConverted = 0;
    uint64_t blocksFailed = 0;
    uint64_t bytesConverted = 0;
    double avgConversionUs = 0.0;
};

class BP16Streamer {
public:
    BP16Streamer() = default;
    explicit BP16Streamer(const BP16StreamerConfig& cfg);
    ~BP16Streamer();

    BP16Streamer(const BP16Streamer&) = delete;
    BP16Streamer& operator=(const BP16Streamer&) = delete;

    bool initialize(const std::string& modelPath);
    bool isInitialized() const { return initialized_; }
    void shutdown();

    // Load a weight block by file offset, convert to bfloat16, store in block cache
    uint64_t loadBlock(uint64_t fileOffset, size_t byteCount);

    // Retrieve converted bfloat16 data for a loaded block
    const bfloat16_t* getBlockData(uint64_t blockId, size_t& outCount) const;

    // Release a block
    bool releaseBlock(uint64_t blockId);

    // Direct conversion: convert an FP32 buffer to bfloat16 (outCount = elements)
    static void convertFp32ToB16(const float* src, bfloat16_t* dst, size_t count);
    static void convertB16ToFp32(const bfloat16_t* src, float* dst, size_t count);

    // Stats
    BP16StreamerStats stats() const;
    void resetStats();

private:
    BP16StreamerConfig cfg_;
    std::atomic<bool> initialized_{false};
    std::atomic<uint64_t> nextBlockId_{1};
    mutable std::mutex blocksMtx_;
    std::unordered_map<uint64_t, BP16Block> blocks_;
    std::string modelPath_;

    mutable std::mutex statsMtx_;
    BP16StreamerStats stats_;
};

} // namespace Deep2
