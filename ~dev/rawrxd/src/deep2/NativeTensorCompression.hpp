#pragma once

// Native, dependency-free, chunked F32 weight storage.
// Each chunk is independently encoded as IEEE F16, BF16, or raw F32.
// Raw chunks are retained whenever the requested absolute-error bound cannot
// be met by either 16-bit representation. No whole-tensor decode is required
// for range reads.
#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <utility>
#include <vector>

namespace RawrXD::TensorCompression {

enum class Encoding : std::uint8_t { F16 = 1, BF16 = 2, F32 = 3 };

class ChunkedF32Storage {
public:
    struct Chunk {
        std::size_t first = 0;
        std::size_t count = 0;
        Encoding encoding = Encoding::F32;
        std::size_t payloadOffset = 0;
        std::size_t payloadBytes = 0;
        float maxAbsError = 0.0f;
    };

    template <class Reader>
    static ChunkedF32Storage BuildFromReader(
        std::size_t elements, float maxAbsError, Reader&& reader,
        std::size_t chunkElements = 4096, bool useRelativeError = false,
        std::size_t maxStoredBytes = std::numeric_limits<std::size_t>::max()) {
        if (!std::isfinite(maxAbsError) || maxAbsError < 0.0f ||
            chunkElements == 0 ||
            elements > std::numeric_limits<std::size_t>::max() / sizeof(float))
            throw std::invalid_argument("invalid ChunkedF32Storage reader input");
        ChunkedF32Storage result;
        result.elements_ = elements;
        result.chunkElements_ = chunkElements;
        std::vector<float> sourceChunk;
        std::vector<std::uint16_t> encoded;
        for (std::size_t first = 0; first < elements;) {
            const std::size_t count = std::min(chunkElements, elements - first);
            sourceChunk.resize(count);
            if (!reader(first, count, sourceChunk.data()))
                throw std::runtime_error("ChunkedF32Storage source read failed");
            encoded.resize(count);
            Chunk chunk;
            chunk.first = first;
            chunk.count = count;
            float halfError = 0.0f, bfloatError = 0.0f;
            float halfMetric = 0.0f, bfloatMetric = 0.0f;
            bool halfValid = true, bfloatValid = true;
            for (std::size_t i = 0; i < count; ++i) {
                const float value = sourceChunk[i];
                const std::uint16_t halfBits = floatToHalf(value);
                const std::uint16_t bfloatBits = floatToBfloat(value);
                const float h = halfToFloat(halfBits);
                const float b = bfloatToFloat(bfloatBits);
                const float eh = (std::isnan(value) ||
                    (std::isinf(value) && h == value)) ? 0.0f : std::fabs(value - h);
                const float eb = (std::isnan(value) ||
                    (std::isinf(value) && b == value)) ? 0.0f : std::fabs(value - b);
                const float scale = useRelativeError && std::isfinite(value)
                    ? std::max(std::fabs(value), std::numeric_limits<float>::min())
                    : 1.0f;
                const float mh = eh / scale;
                const float mb = eb / scale;
                if (!std::isfinite(value) && !std::isnan(value)) {
                    halfValid = halfValid && (h == value);
                    bfloatValid = bfloatValid && (b == value);
                }
                halfValid = halfValid && mh <= maxAbsError;
                bfloatValid = bfloatValid && mb <= maxAbsError;
                halfError = std::max(halfError, eh);
                bfloatError = std::max(bfloatError, eb);
                halfMetric = std::max(halfMetric, mh);
                bfloatMetric = std::max(bfloatMetric, mb);
                encoded[i] = halfBits;
            }
            if (halfValid || bfloatValid) {
                const bool useHalf = halfValid && (!bfloatValid || halfMetric <= bfloatMetric);
                chunk.encoding = useHalf ? Encoding::F16 : Encoding::BF16;
                chunk.maxAbsError = useHalf ? halfError : bfloatError;
                if (!useHalf) {
                    for (std::size_t i = 0; i < count; ++i)
                        encoded[i] = floatToBfloat(sourceChunk[i]);
                }
                chunk.payloadBytes = count * sizeof(std::uint16_t);
                chunk.payloadOffset = result.payload_.size();
                const std::size_t oldSize = result.payload_.size();
                if (oldSize > maxStoredBytes ||
                    chunk.payloadBytes > maxStoredBytes - oldSize)
                    throw std::length_error("compressed tensor exceeds storage budget");
                result.payload_.resize(oldSize + chunk.payloadBytes);
                std::memcpy(result.payload_.data() + oldSize, encoded.data(), chunk.payloadBytes);
            } else {
                chunk.encoding = Encoding::F32;
                chunk.maxAbsError = 0.0f;
                chunk.payloadBytes = count * sizeof(float);
                chunk.payloadOffset = result.payload_.size();
                const std::size_t oldSize = result.payload_.size();
                if (oldSize > maxStoredBytes ||
                    chunk.payloadBytes > maxStoredBytes - oldSize)
                    throw std::length_error("compressed tensor exceeds storage budget");
                result.payload_.resize(oldSize + chunk.payloadBytes);
                std::memcpy(result.payload_.data() + oldSize, sourceChunk.data(), chunk.payloadBytes);
            }
            result.storedBytes_ = result.payload_.size();
            result.maxAbsError_ = std::max(result.maxAbsError_, chunk.maxAbsError);
            result.chunks_.push_back(std::move(chunk));
            first += count;
        }
        return result;
    }

    static ChunkedF32Storage Build(const float* source, std::size_t elements,
                                   float maxAbsError, std::size_t chunkElements = 4096) {
        if (!source && elements)
            throw std::invalid_argument("null ChunkedF32Storage source");
        return BuildFromReader(elements, maxAbsError,
            [source](std::size_t offset, std::size_t count, float* destination) {
                if (count) std::memcpy(destination, source + offset, count * sizeof(float));
                return true;
            }, chunkElements, false);
    }

    std::size_t elements() const noexcept { return elements_; }
    // Compatibility with Deep2 weight consumers.
    std::size_t size() const noexcept { return elements_; }
    void ReadRange(std::size_t first, std::size_t count, float* destination) const {
        if (!DecodeRange(first, count, destination))
            throw std::out_of_range("ChunkedF32Storage::ReadRange outside tensor");
    }
    std::size_t storedBytes() const noexcept { return storedBytes_; }
    std::size_t residentBytes() const noexcept {
        const std::size_t payloadCapacity = payload_.capacity();
        const std::size_t chunkCapacity = chunks_.capacity();
        if (chunkCapacity > (std::numeric_limits<std::size_t>::max() - payloadCapacity) /
                                sizeof(Chunk))
            return std::numeric_limits<std::size_t>::max();
        return payloadCapacity + chunkCapacity * sizeof(Chunk);
    }
    std::size_t originalBytes() const noexcept { return elements_ * sizeof(float); }
    std::size_t chunkCount() const noexcept { return chunks_.size(); }
    float maxAbsError() const noexcept { return maxAbsError_; }
    const std::vector<Chunk>& chunks() const noexcept { return chunks_; }

    bool DecodeRange(std::size_t first, std::size_t count, float* destination) const noexcept {
        if ((!destination && count) || first > elements_ || count > elements_ - first)
            return false;
        if (count == 0) return true;
        const std::size_t end = first + count;
        auto chunkIt = std::lower_bound(
            chunks_.begin(), chunks_.end(), first,
            [](const Chunk& chunk, std::size_t position) {
                return chunk.first + chunk.count <= position;
            });
        for (; chunkIt != chunks_.end() && chunkIt->first < end; ++chunkIt) {
            const Chunk& chunk = *chunkIt;
            const std::size_t chunkEnd = chunk.first + chunk.count;
            const std::size_t begin = std::max(first, chunk.first);
            const std::size_t finish = std::min(end, chunkEnd);
            const std::size_t srcOffset = begin - chunk.first;
            const std::size_t dstOffset = begin - first;
            const std::size_t n = finish - begin;
            if (chunk.encoding == Encoding::F32) {
                std::memcpy(destination + dstOffset,
                    payload_.data() + chunk.payloadOffset + srcOffset * sizeof(float), n * sizeof(float));
            } else {
                for (std::size_t i = 0; i < n; ++i) {
                    std::uint16_t bits;
                    std::memcpy(&bits, payload_.data() + chunk.payloadOffset +
                        (srcOffset + i) * sizeof(bits), sizeof(bits));
                    destination[dstOffset + i] = chunk.encoding == Encoding::F16
                        ? halfToFloat(bits) : bfloatToFloat(bits);
                }
            }
        }
        return true;
    }

    // Returns a stable zero-copy view when every chunk shares one 16-bit encoding.
    // The caller must retain this storage object for the lifetime of the view.
    bool GetUniform16BitView(Encoding& encoding, const std::uint8_t*& data,
                             std::size_t& bytes) const noexcept {
        data = nullptr;
        bytes = 0;
        if (chunks_.empty()) { encoding = Encoding::F16; return elements_ == 0; }
        encoding = chunks_.front().encoding;
        if (encoding == Encoding::F32 ||
            elements_ > std::numeric_limits<std::size_t>::max() / 2)
            return false;
        for (const Chunk& chunk : chunks_)
            if (chunk.encoding != encoding) return false;
        if (payload_.size() != elements_ * 2) return false;
        data = payload_.data();
        bytes = payload_.size();
        return true;
    }

    bool ExportUniform16Bit(Encoding& encoding, std::vector<std::uint8_t>& bytes) const {
        const std::uint8_t* view = nullptr;
        std::size_t viewBytes = 0;
        if (!GetUniform16BitView(encoding, view, viewBytes)) {
            bytes.clear();
            return false;
        }
        if (viewBytes == 0) { bytes.clear(); return true; }
        bytes.assign(view, view + viewBytes);
        return true;
    }

private:
    static std::uint16_t floatToHalf(float value) noexcept {
        std::uint32_t bits;
        std::memcpy(&bits, &value, sizeof(bits));
        const std::uint32_t sign = (bits >> 16) & 0x8000u;
        const std::uint32_t exp = (bits >> 23) & 0xffu;
        std::uint32_t mantissa = bits & 0x7fffffu;
        if (exp == 0xffu) {
            if (!mantissa) return static_cast<std::uint16_t>(sign | 0x7c00u);
            std::uint16_t payload = static_cast<std::uint16_t>(mantissa >> 13);
            return static_cast<std::uint16_t>(sign | 0x7c00u | payload | (payload == 0));
        }
        int halfExp = static_cast<int>(exp) - 127 + 15;
        if (halfExp >= 31) return static_cast<std::uint16_t>(sign | 0x7c00u);
        if (halfExp <= 0) {
            if (halfExp < -10) return static_cast<std::uint16_t>(sign);
            mantissa |= 0x800000u;
            const unsigned shift = static_cast<unsigned>(14 - halfExp);
            std::uint32_t rounded = mantissa >> shift;
            const std::uint32_t remainder = mantissa & ((1u << shift) - 1u);
            const std::uint32_t halfway = 1u << (shift - 1u);
            if (remainder > halfway || (remainder == halfway && (rounded & 1u))) ++rounded;
            return static_cast<std::uint16_t>(sign | rounded);
        }
        std::uint32_t rounded = mantissa >> 13;
        const std::uint32_t remainder = mantissa & 0x1fffu;
        if (remainder > 0x1000u || (remainder == 0x1000u && (rounded & 1u))) {
            if (++rounded == 0x400u) {
                rounded = 0;
                if (++halfExp >= 31) return static_cast<std::uint16_t>(sign | 0x7c00u);
            }
        }
        return static_cast<std::uint16_t>(sign |
            (static_cast<std::uint32_t>(halfExp) << 10) | rounded);
    }

    static float halfToFloat(std::uint16_t h) noexcept {
        const std::uint32_t sign = (static_cast<std::uint32_t>(h & 0x8000u)) << 16;
        std::uint32_t exp = (h >> 10) & 0x1fu;
        std::uint32_t mantissa = h & 0x3ffu;
        std::uint32_t bits;
        if (exp == 0) {
            if (!mantissa) bits = sign;
            else {
                int e = -14;
                while ((mantissa & 0x400u) == 0) { mantissa <<= 1; --e; }
                mantissa &= 0x3ffu;
                bits = sign | (static_cast<std::uint32_t>(e + 127) << 23) |
                    (mantissa << 13);
            }
        } else if (exp == 31) {
            bits = sign | 0x7f800000u | (mantissa << 13);
        } else {
            bits = sign | ((exp + 112u) << 23) | (mantissa << 13);
        }
        float value;
        std::memcpy(&value, &bits, sizeof(value));
        return value;
    }

    static std::uint16_t floatToBfloat(float value) noexcept {
        std::uint32_t bits;
        std::memcpy(&bits, &value, sizeof(bits));
        // Round-to-nearest, ties-to-even. Preserve NaN payload/nonzero mantissa.
        if ((bits & 0x7f800000u) == 0x7f800000u && (bits & 0x007fffffu))
            return static_cast<std::uint16_t>((bits >> 16) | 0x0040u);
        bits += 0x7fffu + ((bits >> 16) & 1u);
        return static_cast<std::uint16_t>(bits >> 16);
    }

    static float bfloatToFloat(std::uint16_t value) noexcept {
        const std::uint32_t bits = static_cast<std::uint32_t>(value) << 16;
        float result;
        std::memcpy(&result, &bits, sizeof(result));
        return result;
    }

    std::size_t elements_ = 0;
    std::size_t chunkElements_ = 0;
    std::size_t storedBytes_ = 0;
    float maxAbsError_ = 0.0f;
    std::vector<Chunk> chunks_;
    std::vector<std::uint8_t> payload_; // one contiguous backing; chunks index into it
};


/*
 * Lossless chunked byte storage for already-quantized GGUF payloads.
 * Each independent block is encoded as an LZ4-compatible raw block only when
 * it shrinks; otherwise the original bytes are retained. Range reads decode
 * only intersecting blocks into caller-owned reusable scratch.
 */
class ChunkedByteStorage {
public:
    enum class Encoding : std::uint8_t { Raw = 0, Lz4Block = 1 };
    struct Chunk {
        std::size_t first = 0;
        std::size_t count = 0;
        std::size_t payloadOffset = 0;
        std::size_t payloadBytes = 0;
        Encoding encoding = Encoding::Raw;
    };

    template <class Reader>
    static ChunkedByteStorage BuildFromReader(
        std::size_t bytes, Reader&& reader, std::size_t chunkBytes = 64u * 1024u,
        bool /*reservedPolicy*/ = false,
        std::size_t maxStoredBytes = std::numeric_limits<std::size_t>::max()) {
        if (chunkBytes == 0)
            throw std::invalid_argument("invalid ChunkedByteStorage chunk size");
        ChunkedByteStorage result;
        result.size_ = bytes;
        std::vector<std::uint8_t> source;
        std::vector<std::uint8_t> encoded;
        for (std::size_t first = 0; first < bytes;) {
            const std::size_t count = std::min(chunkBytes, bytes - first);
            source.resize(count);
            if (!reader(first, count, source.data()))
                throw std::runtime_error("ChunkedByteStorage source read failed");
            encoded = lz4Compress(source.data(), count);
            Chunk chunk;
            chunk.first = first;
            chunk.count = count;
            const bool useLz4 = encoded.size() < count;
            const std::size_t stored = useLz4 ? encoded.size() : count;
            if (result.payload_.size() > maxStoredBytes ||
                stored > maxStoredBytes - result.payload_.size())
                throw std::length_error("compressed byte tensor exceeds storage budget");
            chunk.encoding = useLz4 ? Encoding::Lz4Block : Encoding::Raw;
            chunk.payloadOffset = result.payload_.size();
            chunk.payloadBytes = stored;
            const std::size_t oldSize = result.payload_.size();
            result.payload_.resize(oldSize + stored);
            std::memcpy(result.payload_.data() + oldSize,
                        useLz4 ? encoded.data() : source.data(), stored);
            result.chunks_.push_back(chunk);
            first += count;
        }
        result.storedBytes_ = result.payload_.size();
        return result;
    }

    std::size_t size() const noexcept { return size_; }
    std::size_t storedBytes() const noexcept { return storedBytes_; }
    std::size_t residentBytes() const noexcept {
        const std::size_t payloadCapacity = payload_.capacity();
        const std::size_t chunkCapacity = chunks_.capacity();
        if (chunkCapacity > (std::numeric_limits<std::size_t>::max() - payloadCapacity) /
                                sizeof(Chunk))
            return std::numeric_limits<std::size_t>::max();
        return payloadCapacity + chunkCapacity * sizeof(Chunk);
    }
    std::size_t chunkCount() const noexcept { return chunks_.size(); }
    const std::vector<Chunk>& chunks() const noexcept { return chunks_; }

    void ReadRange(std::size_t first, std::size_t count,
                   std::uint8_t* destination,
                   std::vector<std::uint8_t>& decodeScratch) const {
        if ((!destination && count) || first > size_ || count > size_ - first)
            throw std::out_of_range("ChunkedByteStorage::ReadRange outside tensor");
        if (count == 0) return;
        const std::size_t end = first + count;
        auto chunkIt = std::lower_bound(
            chunks_.begin(), chunks_.end(), first,
            [](const Chunk& chunk, std::size_t position) {
                return chunk.first + chunk.count <= position;
            });
        for (; chunkIt != chunks_.end() && chunkIt->first < end; ++chunkIt) {
            const Chunk& chunk = *chunkIt;
            const std::size_t chunkEnd = chunk.first + chunk.count;
            const std::size_t begin = std::max(first, chunk.first);
            const std::size_t finish = std::min(end, chunkEnd);
            const std::size_t sourceOffset = begin - chunk.first;
            const std::size_t destinationOffset = begin - first;
            const std::size_t copyBytes = finish - begin;
            const std::uint8_t* packed = payload_.data() + chunk.payloadOffset;
            if (chunk.encoding == Encoding::Raw) {
                std::memcpy(destination + destinationOffset,
                            packed + sourceOffset, copyBytes);
                continue;
            }
            decodeScratch.resize(chunk.count);
            if (!lz4Decompress(packed, chunk.payloadBytes,
                               decodeScratch.data(), chunk.count))
                throw std::runtime_error("ChunkedByteStorage LZ4 block is corrupt");
            std::memcpy(destination + destinationOffset,
                        decodeScratch.data() + sourceOffset, copyBytes);
        }
    }

private:
    static std::uint32_t load32(const std::uint8_t* p) noexcept {
        std::uint32_t value;
        std::memcpy(&value, p, sizeof(value));
        return value;
    }

    static void appendLength(std::vector<std::uint8_t>& out, std::size_t length) {
        while (length >= 255) {
            out.push_back(255);
            length -= 255;
        }
        out.push_back(static_cast<std::uint8_t>(length));
    }

    static std::vector<std::uint8_t> lz4Compress(
        const std::uint8_t* source, std::size_t size) {
        std::vector<std::uint8_t> out;
        out.reserve(size);
        if (size < 13) {
            out.push_back(static_cast<std::uint8_t>(std::min<std::size_t>(size, 15) << 4));
            if (size >= 15) appendLength(out, size - 15);
            out.insert(out.end(), source, source + size);
            return out;
        }
        constexpr std::uint32_t kHashBits = 16;
        constexpr std::uint32_t kHashSize = 1u << kHashBits;
        std::vector<std::int32_t> table(kHashSize, -1);
        auto hashAt = [&](std::size_t p) {
            return (load32(source + p) * 2654435761u) >> (32 - kHashBits);
        };
        std::size_t anchor = 0;
        std::size_t pos = 0;
        while (pos <= size - 12) {
            const std::uint32_t h = hashAt(pos);
            const std::int32_t reference = table[h];
            table[h] = static_cast<std::int32_t>(pos);
            if (reference < 0 ||
                pos - static_cast<std::size_t>(reference) > 65535u ||
                std::memcmp(source + reference, source + pos, 4) != 0) {
                ++pos;
                continue;
            }
            const std::size_t ref = static_cast<std::size_t>(reference);
            std::size_t matchLength = 4;
            while (pos + matchLength < size - 5 &&
                   source[ref + matchLength] == source[pos + matchLength])
                ++matchLength;
            const std::size_t literalLength = pos - anchor;
            const std::size_t matchCode = matchLength - 4;
            const std::size_t tokenIndex = out.size();
            out.push_back(0);
            out[tokenIndex] = static_cast<std::uint8_t>(
                (std::min<std::size_t>(literalLength, 15) << 4) |
                 std::min<std::size_t>(matchCode, 15));
            if (literalLength >= 15) appendLength(out, literalLength - 15);
            out.insert(out.end(), source + anchor, source + pos);
            const std::uint16_t distance = static_cast<std::uint16_t>(pos - ref);
            out.push_back(static_cast<std::uint8_t>(distance & 0xffu));
            out.push_back(static_cast<std::uint8_t>(distance >> 8));
            if (matchCode >= 15) appendLength(out, matchCode - 15);
            pos += matchLength;
            anchor = pos;
            // Seed positions inside the match to improve subsequent matches.
            for (std::size_t p = pos > matchLength ? pos - matchLength + 1 : 0;
                 p + 4 <= pos && p <= size - 4; ++p)
                table[hashAt(p)] = static_cast<std::int32_t>(p);
        }
        const std::size_t literalLength = size - anchor;
        const std::size_t tokenIndex = out.size();
        out.push_back(static_cast<std::uint8_t>(std::min<std::size_t>(literalLength, 15) << 4));
        if (literalLength >= 15) appendLength(out, literalLength - 15);
        out.insert(out.end(), source + anchor, source + size);
        (void)tokenIndex;
        return out;
    }

    static bool readExtendedLength(const std::uint8_t* source, std::size_t size,
                                   std::size_t& cursor, std::size_t& length) noexcept {
        std::uint8_t part = 255;
        while (part == 255) {
            if (cursor >= size) return false;
            part = source[cursor++];
            if (length > std::numeric_limits<std::size_t>::max() - part) return false;
            length += part;
        }
        return true;
    }

    static bool lz4Decompress(const std::uint8_t* source, std::size_t sourceSize,
                              std::uint8_t* destination,
                              std::size_t destinationSize) noexcept {
        std::size_t src = 0, dst = 0;
        while (src < sourceSize) {
            const std::uint8_t token = source[src++];
            std::size_t literalLength = token >> 4;
            if (literalLength == 15 &&
                !readExtendedLength(source, sourceSize, src, literalLength))
                return false;
            if (literalLength > sourceSize - src ||
                literalLength > destinationSize - dst)
                return false;
            if (literalLength) {
                std::memcpy(destination + dst, source + src, literalLength);
                src += literalLength;
                dst += literalLength;
            }
            if (src == sourceSize) break;
            if (sourceSize - src < 2) return false;
            const std::size_t distance =
                static_cast<std::size_t>(source[src]) |
                (static_cast<std::size_t>(source[src + 1]) << 8);
            src += 2;
            if (!distance || distance > dst) return false;
            std::size_t matchLength = (token & 0x0fu) + 4u;
            if ((token & 0x0fu) == 15 &&
                !readExtendedLength(source, sourceSize, src, matchLength))
                return false;
            if (matchLength > destinationSize - dst) return false;
            for (std::size_t i = 0; i < matchLength; ++i)
                destination[dst + i] = destination[dst + i - distance];
            dst += matchLength;
        }
        return dst == destinationSize;
    }

    std::size_t size_ = 0;
    std::size_t storedBytes_ = 0;
    std::vector<Chunk> chunks_;
    std::vector<std::uint8_t> payload_;
};

} // namespace RawrXD::TensorCompression
