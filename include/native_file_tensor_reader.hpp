#pragma once
// Stream compressed weight blocks from a file without materializing full tensors.
// Source byte ranges are preserved exactly, including GGML quantized payloads.
#include "native_compressed_tensor.hpp"
#include <cstdint>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace rawrxd::compression {
class FileTensorReader {
public:
    FileTensorReader(std::string path, std::uint64_t base, std::uint64_t length)
        : file_(std::move(path), std::ios::binary), base_(base), length_(length) {
        if (!file_) throw std::runtime_error("cannot open tensor source");
        file_.seekg(0, std::ios::end);
        const auto end = file_.tellg();
        if (end < 0 || static_cast<std::uint64_t>(end) < base_ ||
            length_ > static_cast<std::uint64_t>(end) - base_)
            throw std::out_of_range("tensor outside file");
    }
    std::uint64_t size() const noexcept { return length_; }
    void read(std::uint64_t offset, std::uint8_t* dst, std::size_t bytes) {
        if (offset > length_ || bytes > length_ - offset || (bytes && !dst) ||
            base_ + offset > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max()) ||
            bytes > static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max()))
            throw std::out_of_range("invalid source read");
        if (!bytes) return;
        file_.clear();
        file_.seekg(static_cast<std::streamoff>(base_ + offset));
        file_.read(reinterpret_cast<char*>(dst), static_cast<std::streamsize>(bytes));
        if (!file_) throw std::runtime_error("short tensor read");
    }
    // Process one block at a time. The sink can persist the compressed payload
    // to a dedicated weight store without ever allocating the entire tensor.
    template<class Sink>
    void for_each_compressed_block(std::size_t block_bytes, Sink&& sink) {
        if (!block_bytes) throw std::invalid_argument("zero block size");
        std::vector<std::uint8_t> scratch;
        for (std::uint64_t offset = 0; offset < length_;) {
            const auto count = static_cast<std::size_t>(
                std::min<std::uint64_t>(block_bytes, length_ - offset));
            scratch.resize(count);
            read(offset, scratch.data(), count);
            auto encoded = encode(scratch.data(), count);
            sink(offset, encoded);
            offset += count;
        }
    }
private:
    std::ifstream file_;
    std::uint64_t base_;
    std::uint64_t length_;
};
} // namespace rawrxd::compression
