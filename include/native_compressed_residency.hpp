#pragma once
// Native compressed residency: bounded, lossless block cache.
// Independent of GGUF parsing and GPU ownership. C++17.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <list>
#include <mutex>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

namespace rawrxd::compression {
struct Block {
    std::vector<std::uint8_t> payload;
    std::size_t decoded_size = 0;
    bool rle = false;
    bool lz4 = false;
    // Immutable content generation; callers must change it when a block is replaced.
    std::uint64_t generation = 0;
};

namespace detail {
inline std::uint32_t load32le(const std::uint8_t* p) noexcept {
    return std::uint32_t(p[0]) | (std::uint32_t(p[1]) << 8) |
           (std::uint32_t(p[2]) << 16) | (std::uint32_t(p[3]) << 24);
}
inline void emit_length(std::vector<std::uint8_t>& out, std::size_t length) {
    while (length >= 255) {
        out.push_back(255);
        length -= 255;
    }
    out.push_back(static_cast<std::uint8_t>(length));
}
inline std::vector<std::uint8_t> encode_lz4_block(
    const std::uint8_t* data, std::size_t size) {
    std::vector<std::uint8_t> out;
    if (size < 8) return out;
    constexpr std::size_t hashBits = 16;
    constexpr std::size_t hashSize = std::size_t{1} << hashBits;
    std::vector<std::int64_t> table(hashSize, -1);
    out.reserve(size);
    std::size_t anchor = 0;
    std::size_t cursor = 0;
    while (cursor + 4 <= size) {
        const auto word = load32le(data + cursor);
        const auto hash = static_cast<std::size_t>(
            (word * 2654435761u) >> (32 - hashBits));
        const auto previous = table[hash];
        table[hash] = static_cast<std::int64_t>(cursor);
        if (previous < 0 || cursor - static_cast<std::size_t>(previous) > 65535u ||
            std::memcmp(data + previous, data + cursor, 4) != 0) {
            ++cursor;
            continue;
        }

        const auto matchStart = cursor;
        const auto reference = static_cast<std::size_t>(previous);
        std::size_t matchLength = 4;
        while (matchStart + matchLength < size &&
               data[reference + matchLength] == data[matchStart + matchLength])
            ++matchLength;

        const auto literalLength = matchStart - anchor;
        const auto matchCode = matchLength - 4;
        const auto tokenIndex = out.size();
        out.push_back(0);
        out[tokenIndex] = static_cast<std::uint8_t>(
            (std::min<std::size_t>(literalLength, 15) << 4) |
             std::min<std::size_t>(matchCode, 15));
        if (literalLength >= 15) emit_length(out, literalLength - 15);
        out.insert(out.end(), data + anchor, data + matchStart);
        const auto distance = matchStart - reference;
        out.push_back(static_cast<std::uint8_t>(distance & 0xffu));
        out.push_back(static_cast<std::uint8_t>((distance >> 8) & 0xffu));
        if (matchCode >= 15) emit_length(out, matchCode - 15);

        cursor = matchStart + matchLength;
        anchor = cursor;
        // Seed hashes within the matched region so repeated structures are found
        // without rescanning bytes that cannot begin a complete four-byte key.
        auto seed = matchStart + 1;
        while (seed + 4 <= cursor && seed + 4 <= size) {
            const auto seedWord = load32le(data + seed);
            const auto seedHash = static_cast<std::size_t>(
                (seedWord * 2654435761u) >> (32 - hashBits));
            table[seedHash] = static_cast<std::int64_t>(seed);
            ++seed;
        }
    }

    const auto tail = size - anchor;
    if (tail || out.empty()) {
        const auto tokenIndex = out.size();
        out.push_back(static_cast<std::uint8_t>(std::min<std::size_t>(tail, 15) << 4));
        if (tail >= 15) emit_length(out, tail - 15);
        out.insert(out.end(), data + anchor, data + size);
        (void)tokenIndex;
    }
    return out;
}

inline std::vector<std::uint8_t> decode_lz4_block(const Block& block) {
    const auto& input = block.payload;
    std::vector<std::uint8_t> output;
    output.reserve(block.decoded_size);
    std::size_t cursor = 0;
    auto read_extended = [&](std::size_t base) {
        std::size_t length = base;
        if (base == 15) {
            for (;;) {
                if (cursor >= input.size())
                    throw std::runtime_error("truncated LZ4 length");
                const auto extra = input[cursor++];
                if (extra > block.decoded_size - std::min(length, block.decoded_size))
                    throw std::runtime_error("LZ4 length overflow");
                length += extra;
                if (extra != 255) break;
            }
        }
        return length;
    };

    while (cursor < input.size()) {
        const auto token = input[cursor++];
        const auto literalLength = read_extended(token >> 4);
        if (literalLength > input.size() - cursor ||
            literalLength > block.decoded_size - output.size())
            throw std::runtime_error("invalid LZ4 literal range");
        output.insert(output.end(), input.begin() + static_cast<std::ptrdiff_t>(cursor),
                      input.begin() + static_cast<std::ptrdiff_t>(cursor + literalLength));
        cursor += literalLength;
        if (cursor == input.size()) break;
        if (input.size() - cursor < 2)
            throw std::runtime_error("truncated LZ4 match offset");
        const auto distance = std::size_t(input[cursor]) |
                              (std::size_t(input[cursor + 1]) << 8);
        cursor += 2;
        if (!distance || distance > output.size())
            throw std::runtime_error("invalid LZ4 match offset");
        const auto matchLength = read_extended(token & 0x0fu) + 4;
        if (matchLength > block.decoded_size - output.size())
            throw std::runtime_error("LZ4 output exceeds decoded size");
        for (std::size_t i = 0; i < matchLength; ++i)
            output.push_back(output[output.size() - distance]);
    }
    if (output.size() != block.decoded_size)
        throw std::runtime_error("LZ4 decoded size mismatch");
    return output;
}
} // namespace detail

// Byte-level, lossless block codecs. RLE is best for long runs; LZ4-style
// matching handles repeated structures in quantized weights; raw is the
// bounded fallback when compression cannot beat the original representation.
inline Block encode(const std::uint8_t* data, std::size_t size) {
    if (size && !data) throw std::invalid_argument("null input");
    Block out;
    out.decoded_size = size;
    if (!size) return out;

    std::vector<std::uint8_t> best(data, data + size);
    bool bestRle = false;
    bool bestLz4 = false;

    std::vector<std::uint8_t> rle;
    rle.reserve(std::min(size, std::size_t{4096}));
    bool rleViable = true;
    for (std::size_t i = 0; i < size;) {
        std::size_t run = 1;
        while (run < 255 && run < size - i && data[i + run] == data[i]) ++run;
        if (rle.size() > size - 2) {
            rleViable = false;
            break;
        }
        rle.push_back(static_cast<std::uint8_t>(run));
        rle.push_back(data[i]);
        i += run;
    }
    if (rleViable && rle.size() < best.size()) {
        best.swap(rle);
        bestRle = true;
    }

    auto lz4 = detail::encode_lz4_block(data, size);
    if (!lz4.empty() && lz4.size() < best.size()) {
        best.swap(lz4);
        bestRle = false;
        bestLz4 = true;
    }

    out.payload = std::move(best);
    out.rle = bestRle;
    out.lz4 = bestLz4;
    return out;
}
inline std::vector<std::uint8_t> decode(const Block& block) {
    if (block.rle && block.lz4)
        throw std::runtime_error("ambiguous compressed block codec");
    if (block.lz4) return detail::decode_lz4_block(block);
    if (!block.rle) {
        if (block.payload.size() != block.decoded_size)
            throw std::runtime_error("invalid raw block length");
        return block.payload;
    }
    if (block.payload.size() % 2) throw std::runtime_error("invalid RLE block");
    std::vector<std::uint8_t> out;
    out.reserve(block.decoded_size);
    for (std::size_t i = 0; i < block.payload.size(); i += 2) {
        const auto count = block.payload[i];
        if (!count || out.size() > block.decoded_size ||
            count > block.decoded_size - out.size())
            throw std::runtime_error("invalid RLE run");
        out.insert(out.end(), count, block.payload[i + 1]);
    }
    if (out.size() != block.decoded_size)
        throw std::runtime_error("truncated RLE block");
    return out;
}

// Returned bytes are owned by the caller. No raw pointer survives eviction.
// The cache never exceeds capacity; oversized blocks decode without caching.
class BoundedDecodeCache {
public:
    explicit BoundedDecodeCache(std::size_t capacity) : capacity_(capacity) {}
    std::vector<std::uint8_t> get(std::uint64_t id, const Block& block) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto found = entries_.find(id);
        if (found != entries_.end()) {
            if (found->second.generation == block.generation) {
                order_.splice(order_.begin(), order_, found->second.position);
                return found->second.bytes;
            }
            used_ -= found->second.bytes.size();
            order_.erase(found->second.position);
            entries_.erase(found);
        }
        auto bytes = decode(block);
        if (bytes.size() > capacity_) return bytes;
        while (used_ > capacity_ - bytes.size() && !order_.empty()) {
            auto victim = order_.back();
            auto it = entries_.find(victim);
            used_ -= it->second.bytes.size();
            entries_.erase(it);
            order_.pop_back();
        }
        order_.push_front(id);
        used_ += bytes.size();
        entries_.emplace(id, Entry{bytes, order_.begin(), block.generation});
        return bytes;
    }
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        entries_.clear();
        order_.clear();
        used_ = 0;
    }
    std::size_t resident_bytes() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return used_;
    }
private:
    struct Entry {
        std::vector<std::uint8_t> bytes;
        std::list<std::uint64_t>::iterator position;
        std::uint64_t generation;
    };
    const std::size_t capacity_;
    mutable std::mutex mutex_;
    std::size_t used_ = 0;
    std::list<std::uint64_t> order_;
    std::unordered_map<std::uint64_t, Entry> entries_;
};
} // namespace rawrxd::compression
