// ============================================================================
// BP16Streamer.cpp — Real block/weight streaming with bfloat16 conversion
// ============================================================================
#include "BP16Streamer.hpp"
#include <cstdio>
#include <chrono>
#include <fstream>

namespace Deep2 {

BP16Streamer::BP16Streamer(const BP16StreamerConfig& cfg) : cfg_(cfg) {}

BP16Streamer::~BP16Streamer() { shutdown(); }

bool BP16Streamer::initialize(const std::string& modelPath) {
    if (initialized_) return true;
    modelPath_ = modelPath;
    initialized_ = true;
    return true;
}

void BP16Streamer::shutdown() {
    initialized_ = false;
    std::lock_guard<std::mutex> lk(blocksMtx_);
    blocks_.clear();
}

uint64_t BP16Streamer::loadBlock(uint64_t fileOffset, size_t byteCount) {
    if (!initialized_ || byteCount == 0) return 0;

    uint64_t blockId = nextBlockId_.fetch_add(1);
    BP16Block block;
    block.blockId = blockId;
    block.fileOffset = fileOffset;
    block.byteCount = byteCount;
    block.state = BP16BlockState::Loading;

    auto t0 = std::chrono::high_resolution_clock::now();

    // Read raw bytes from model file
    std::ifstream file(modelPath_, std::ios::binary);
    if (!file) {
        std::fprintf(stderr, "[BP16Streamer] failed to open %s\n", modelPath_.c_str());
        block.state = BP16BlockState::Failed;
        block.errorCode = 1;
        return 0;
    }
    file.seekg(static_cast<std::streamoff>(fileOffset));
    std::vector<float> fp32Data(byteCount / sizeof(float) + 1);
    file.read(reinterpret_cast<char*>(fp32Data.data()),
              static_cast<std::streamsize>(byteCount));
    size_t bytesRead = static_cast<size_t>(file.gcount());
    file.close();

    if (bytesRead == 0) {
        block.state = BP16BlockState::Failed;
        block.errorCode = 2;
        return 0;
    }

    size_t elements = bytesRead / sizeof(float);
    block.b16Data.resize(elements);
    convertFp32ToB16(fp32Data.data(), block.b16Data.data(), elements);

    auto t1 = std::chrono::high_resolution_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();

    block.state = BP16BlockState::Ready;

    {
        std::lock_guard<std::mutex> lk(blocksMtx_);
        // Evict oldest if at capacity
        if (blocks_.size() >= cfg_.maxBlocks) {
            auto oldest = blocks_.begin();
            blocks_.erase(oldest);
        }
        blocks_[blockId] = std::move(block);
    }

    {
        std::lock_guard<std::mutex> lk(statsMtx_);
        ++stats_.blocksLoaded;
        ++stats_.blocksConverted;
        stats_.bytesConverted += elements * sizeof(bfloat16_t);
        stats_.avgConversionUs = (stats_.avgConversionUs * (stats_.blocksConverted - 1) + us)
                                 / stats_.blocksConverted;
    }

    return blockId;
}

const bfloat16_t* BP16Streamer::getBlockData(uint64_t blockId, size_t& outCount) const {
    std::lock_guard<std::mutex> lk(blocksMtx_);
    auto it = blocks_.find(blockId);
    if (it == blocks_.end() || it->second.state != BP16BlockState::Ready) {
        outCount = 0;
        return nullptr;
    }
    outCount = it->second.b16Data.size();
    return it->second.b16Data.data();
}

bool BP16Streamer::releaseBlock(uint64_t blockId) {
    std::lock_guard<std::mutex> lk(blocksMtx_);
    return blocks_.erase(blockId) > 0;
}

void BP16Streamer::convertFp32ToB16(const float* src, bfloat16_t* dst, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        dst[i] = bfloat16_t(src[i]);
    }
}

void BP16Streamer::convertB16ToFp32(const bfloat16_t* src, float* dst, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        dst[i] = src[i].toFloat();
    }
}

BP16StreamerStats BP16Streamer::stats() const {
    std::lock_guard<std::mutex> lk(statsMtx_);
    return stats_;
}

void BP16Streamer::resetStats() {
    std::lock_guard<std::mutex> lk(statsMtx_);
    stats_ = BP16StreamerStats{};
}

} // namespace Deep2
