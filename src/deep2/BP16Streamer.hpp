// ============================================================================
// BP16Streamer.hpp — Stub header for BP16 weight streaming
// Provides zero-copy mapped weight access from BP16 files.
// ============================================================================

#ifndef BP16_STREAMER_HPP
#define BP16_STREAMER_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

// Minimal GGML type enum subset for BP16 records
enum class GGMLType : int {
    GGML_TYPE_F32  = 0,
    GGML_TYPE_F16  = 1,
    GGML_TYPE_Q4_0 = 2,
    GGML_TYPE_Q5_0 = 3,
    GGML_TYPE_Q8_0 = 8,
    GGML_TYPE_Q4_K = 12,
    GGML_TYPE_Q5_K = 13,
    GGML_TYPE_Q6_K = 14,
};

class BP16Streamer {
public:
    struct Record {
        std::string name;
        std::vector<size_t> dimensions;
        GGMLType type = GGMLType::GGML_TYPE_F32;
    };

    BP16Streamer() = default;
    ~BP16Streamer() { close(); }

    bool open(const char* path);
    void close();

    const char* error() const;

    size_t tensorCount() const;
    size_t fileSize() const;

    const Record* find(const std::string& name) const;
    const std::vector<Record>& records() const;

    bool map_tensor(const std::string& name, const uint8_t*& data, size_t& bytes);

private:
    std::vector<Record> records_;
    mutable std::string lastError_;
    bool opened_ = false;
};

#endif // BP16_STREAMER_HPP
