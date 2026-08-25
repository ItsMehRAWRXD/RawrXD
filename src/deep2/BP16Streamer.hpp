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

// Use Deep2::GGMLType from GGUFLoader.hpp — forward declare only
namespace Deep2 { enum class GGMLType : uint32_t; }

class BP16Streamer {
public:
    struct Record {
        std::string name;
        std::vector<size_t> dimensions;
        Deep2::GGMLType type = static_cast<Deep2::GGMLType>(0);
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
