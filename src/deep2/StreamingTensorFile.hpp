#pragma once
// Bounded-memory, read-only RWT1 access; existing C++17 and zlib only.
// Not thread-safe: give each inference request its own file handle.
#include "TensorAwareLossless.hpp"
#include <algorithm>
#include <cstdint>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>
namespace rawrxd::weights {
class StreamingTensorFile {
    struct Index { uint64_t offset; uint32_t encoded, plain, crc; BlockCodec codec; };
    std::ifstream file_;
    Tensor metadata_;
    std::vector<Index> index_;
    uint64_t file_size_ = 0;
    static uint32_t read32(std::istream& f) {
        uint8_t b[4];
        if (!f.read(reinterpret_cast<char*>(b), 4)) throw std::runtime_error("truncated RWT1");
        return uint32_t(b[0]) | uint32_t(b[1])<<8 | uint32_t(b[2])<<16 | uint32_t(b[3])<<24;
    }
    static uint64_t read64(std::istream& f) {
        uint64_t lo=read32(f), hi=read32(f);
        return lo|(hi<<32);
    }
public:
    explicit StreamingTensorFile(const std::string& path,
            uint64_t max_plain_bytes=(uint64_t(1)<<40),
            uint32_t max_block_bytes=(1u<<24))
        : file_(path, std::ios::binary) {
        if (!file_) throw std::runtime_error("cannot open RWT1");
        file_.seekg(0, std::ios::end);
        auto end=file_.tellg();
        if (end < 0) throw std::runtime_error("cannot size RWT1");
        file_size_=static_cast<uint64_t>(end);
        file_.seekg(0);
        if (read32(file_)!=0x31545752u || read32(file_)!=1)
            throw std::runtime_error("invalid RWT1 version");
        metadata_.plain_size=read64(file_);
        metadata_.block_size=read32(file_);
        uint32_t element=read32(file_), count=read32(file_);
        if (!metadata_.block_size || metadata_.block_size>max_block_bytes ||
            (element!=1 && element!=2 && element!=4 && element!=8) ||
            metadata_.plain_size>max_plain_bytes ||
            (metadata_.plain_size/metadata_.block_size +
             (metadata_.plain_size%metadata_.block_size!=0))!=count ||
            uint64_t(count)*16 > file_size_-std::min<uint64_t>(file_size_,28))
            throw std::runtime_error("invalid RWT1 dimensions");
        metadata_.element_bytes=static_cast<uint8_t>(element);
        index_.reserve(count);
        uint64_t sum=0;
        for (uint32_t i=0;i<count;++i) {
            uint32_t codec=read32(file_), plain=read32(file_);
            uint32_t crc=read32(file_), encoded=read32(file_);
            uint32_t expected=static_cast<uint32_t>(
                std::min<uint64_t>(metadata_.block_size,metadata_.plain_size-sum));
            auto offset=file_.tellg();
            if (offset<0 || codec>3 || !expected || plain!=expected ||
                encoded>uint64_t(max_block_bytes)+65536 ||
                (codec==0 && encoded!=plain) ||
                uint64_t(offset)>file_size_ ||
                encoded>file_size_-uint64_t(offset))
                throw std::runtime_error("invalid RWT1 block");
            index_.push_back({uint64_t(offset),encoded,plain,crc,
                              static_cast<BlockCodec>(codec)});
            sum+=plain;
            file_.seekg(static_cast<std::streamoff>(encoded),std::ios::cur);
            if (!file_) throw std::runtime_error("truncated RWT1 payload");
        }
        auto final_pos=file_.tellg();
        if (sum!=metadata_.plain_size || final_pos<0 ||
            uint64_t(final_pos)!=file_size_)
            throw std::runtime_error("RWT1 trailing data or size mismatch");
    }
    uint64_t plain_size() const { return metadata_.plain_size; }
    uint32_t block_size() const { return metadata_.block_size; }
    size_t block_count() const { return index_.size(); }
    // Only one compressed payload and one decoded block are allocated per call.
    std::vector<uint8_t> read_block(size_t i) {
        if (i>=index_.size()) throw std::out_of_range("RWT1 block index");
        const auto& e=index_[i];
        file_.clear();
        file_.seekg(static_cast<std::streamoff>(e.offset));
        Block b;
        b.codec=e.codec; b.plain_size=e.plain; b.crc32_plain=e.crc;
        b.payload.resize(e.encoded);
        if (!file_.read(reinterpret_cast<char*>(b.payload.data()),e.encoded))
            throw std::runtime_error("RWT1 block read failed");
        Tensor one;
        one.block_size=metadata_.block_size;
        one.element_bytes=metadata_.element_bytes;
        one.plain_size=e.plain;
        one.blocks.push_back(std::move(b));
        return decode_block(one,0);
    }
};
} // namespace rawrxd::weights
