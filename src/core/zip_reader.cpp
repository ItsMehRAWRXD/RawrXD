#include "zip_reader.h"

#include <cstring>
#include <filesystem>
#include <fstream>

namespace RawrXD {

namespace {

// ---- CRC-32, as the ZIP format requires ----
uint32_t Crc32Table(uint8_t index) {
    static uint32_t table[256];
    static bool built = false;
    if (!built) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) {
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            }
            table[i] = c;
        }
        built = true;
    }
    return table[index];
}

uint32_t Crc32(const uint8_t* data, size_t length) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < length; ++i) {
        crc = Crc32Table((crc ^ data[i]) & 0xFF) ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

// ---- DEFLATE bit reader ----
class BitReader {
public:
    BitReader(const uint8_t* data, size_t size) : data_(data), size_(size) {}

    // Reads `count` bits, least significant bit first.
    uint32_t bits(int count) {
        uint32_t value = 0;
        for (int i = 0; i < count; ++i) {
            if (bitCount_ == 0) {
                if (pos_ >= size_) { overrun_ = true; return value; }
                bitBuffer_ = data_[pos_++];
                bitCount_ = 8;
            }
            value |= static_cast<uint32_t>(bitBuffer_ & 1) << i;
            bitBuffer_ >>= 1;
            --bitCount_;
        }
        return value;
    }

    void alignToByte() { bitCount_ = 0; }

    // Copies `count` bytes straight through, for stored blocks.
    bool copyBytes(uint8_t* out, size_t count) {
        if (pos_ + count > size_) return false;
        if (out) memcpy(out, data_ + pos_, count);
        pos_ += count;
        return true;
    }

    size_t bytePosition() const { return pos_; }
    void setBytePosition(size_t p) { pos_ = p; }
    bool overrun() const { return overrun_; }
    size_t size() const { return size_; }

private:
    const uint8_t* data_ = nullptr;
    size_t size_ = 0;
    size_t pos_ = 0;
    uint8_t bitBuffer_ = 0;
    int bitCount_ = 0;
    bool overrun_ = false;
};

// ---- Canonical Huffman decoder ----
struct Huffman {
    // counts[len] = number of codes of that length, symbols = symbols in
    // canonical order.
    int counts[16] = {0};
    std::vector<int> symbols;

    bool build(const uint8_t* lengths, int count) {
        memset(counts, 0, sizeof(counts));
        for (int i = 0; i < count; ++i) {
            if (lengths[i] > 15) return false;
            counts[lengths[i]]++;
        }
        counts[0] = 0;

        // Check that the code set is not over-subscribed.
        int left = 1;
        for (int len = 1; len <= 15; ++len) {
            left <<= 1;
            left -= counts[len];
            if (left < 0) return false;
        }

        int offsets[16];
        offsets[0] = 0;
        offsets[1] = 0;
        for (int len = 1; len < 15; ++len) {
            offsets[len + 1] = offsets[len] + counts[len];
        }

        symbols.assign(static_cast<size_t>(count), 0);
        for (int i = 0; i < count; ++i) {
            if (lengths[i]) {
                symbols[static_cast<size_t>(offsets[lengths[i]]++)] = i;
            }
        }
        return true;
    }

    // Decodes one symbol. Returns -1 on an invalid code.
    int decode(BitReader& reader) const {
        int code = 0, first = 0, index = 0;
        for (int len = 1; len <= 15; ++len) {
            code |= static_cast<int>(reader.bits(1));
            int count = counts[len];
            if (code - first < count) {
                size_t at = static_cast<size_t>(index + (code - first));
                if (at >= symbols.size()) return -1;
                return symbols[at];
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
            if (reader.overrun()) return -1;
        }
        return -1;
    }
};

const uint16_t kLengthBase[29] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
    67, 83, 99, 115, 131, 163, 195, 227, 258
};
const uint8_t kLengthExtra[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
    4, 4, 4, 4, 5, 5, 5, 5, 0
};
const uint16_t kDistanceBase[30] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513,
    769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
};
const uint8_t kDistanceExtra[30] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
    9, 9, 10, 10, 11, 11, 12, 12, 13, 13
};

// Builds the fixed Huffman tables from RFC 1951.
void BuildFixedTables(Huffman& literals, Huffman& distances) {
    uint8_t litLengths[288];
    for (int i = 0; i < 144; ++i) litLengths[i] = 8;
    for (int i = 144; i < 256; ++i) litLengths[i] = 9;
    for (int i = 256; i < 280; ++i) litLengths[i] = 7;
    for (int i = 280; i < 288; ++i) litLengths[i] = 8;
    literals.build(litLengths, 288);

    uint8_t distLengths[30];
    for (int i = 0; i < 30; ++i) distLengths[i] = 5;
    distances.build(distLengths, 30);
}

bool ReadDynamicTables(BitReader& reader, Huffman& literals, Huffman& distances) {
    int hlit = static_cast<int>(reader.bits(5)) + 257;
    int hdist = static_cast<int>(reader.bits(5)) + 1;
    int hclen = static_cast<int>(reader.bits(4)) + 4;
    if (reader.overrun()) return false;
    if (hlit > 286 || hdist > 30) return false;

    static const int kOrder[19] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

    uint8_t codeLengths[19] = {0};
    for (int i = 0; i < hclen; ++i) {
        codeLengths[kOrder[i]] = static_cast<uint8_t>(reader.bits(3));
    }
    if (reader.overrun()) return false;

    Huffman codeTable;
    if (!codeTable.build(codeLengths, 19)) return false;

    uint8_t lengths[320] = {0};
    int index = 0;
    while (index < hlit + hdist) {
        int symbol = codeTable.decode(reader);
        if (symbol < 0) return false;

        if (symbol < 16) {
            lengths[index++] = static_cast<uint8_t>(symbol);
        } else if (symbol == 16) {
            if (index == 0) return false;
            uint8_t previous = lengths[index - 1];
            int repeat = 3 + static_cast<int>(reader.bits(2));
            while (repeat-- && index < hlit + hdist) lengths[index++] = previous;
        } else if (symbol == 17) {
            int repeat = 3 + static_cast<int>(reader.bits(3));
            while (repeat-- && index < hlit + hdist) lengths[index++] = 0;
        } else {
            int repeat = 11 + static_cast<int>(reader.bits(7));
            while (repeat-- && index < hlit + hdist) lengths[index++] = 0;
        }
        if (reader.overrun()) return false;
    }

    if (!literals.build(lengths, hlit)) return false;
    if (!distances.build(lengths + hlit, hdist)) return false;
    return true;
}

} // namespace

bool inflateRaw(const uint8_t* data, size_t size, std::string& out, size_t expectedSize) {
    if (!data) return false;

    BitReader reader(data, size);
    out.clear();
    if (expectedSize) out.reserve(expectedSize);

    // A decompression bomb, or a malformed stream that never ends, must not
    // be able to exhaust memory. The archive records the expected size, so
    // the limit is derived from it.
    const size_t kMaxOutput = 256u * 1024u * 1024u;
    size_t limit = expectedSize ? expectedSize + (expectedSize / 4) + 1024 : kMaxOutput;
    if (limit > kMaxOutput) limit = kMaxOutput;

    for (;;) {
        int final = static_cast<int>(reader.bits(1));
        int type = static_cast<int>(reader.bits(2));
        if (reader.overrun()) return false;

        if (type == 0) {
            // Stored: length then the raw bytes.
            reader.alignToByte();
            uint16_t length = static_cast<uint16_t>(reader.bits(16));
            uint16_t inverse = static_cast<uint16_t>(reader.bits(16));
            if (reader.overrun()) return false;
            if (static_cast<uint16_t>(~inverse) != length) return false;

            if (out.size() + length > limit) return false;
            size_t base = out.size();
            out.resize(base + length);
            if (length && !reader.copyBytes(reinterpret_cast<uint8_t*>(&out[base]), length)) {
                return false;
            }
        } else if (type == 1 || type == 2) {
            Huffman literals, distances;
            if (type == 1) {
                BuildFixedTables(literals, distances);
            } else {
                if (!ReadDynamicTables(reader, literals, distances)) return false;
            }

            for (;;) {
                int symbol = literals.decode(reader);
                if (symbol < 0) return false;

                if (out.size() >= limit) return false;
                if (symbol < 256) {
                    out.push_back(static_cast<char>(symbol));
                } else if (symbol == 256) {
                    break;
                } else {
                    symbol -= 257;
                    if (symbol >= 29) return false;
                    int length = kLengthBase[symbol] + static_cast<int>(reader.bits(kLengthExtra[symbol]));

                    int distanceSymbol = distances.decode(reader);
                    if (distanceSymbol < 0 || distanceSymbol >= 30) return false;
                    size_t distance = kDistanceBase[distanceSymbol] +
                                     static_cast<size_t>(reader.bits(kDistanceExtra[distanceSymbol]));
                    if (reader.overrun()) return false;
                    if (distance > out.size()) return false;

                    if (out.size() + static_cast<size_t>(length) > limit) return false;
                    size_t start = out.size() - distance;
                    for (int i = 0; i < length; ++i) {
                        out.push_back(out[start + static_cast<size_t>(i)]);
                    }
                }
                if (reader.overrun()) return false;
            }
        } else {
            return false;   // reserved block type
        }

        if (final) break;
    }

    return true;
}

// ---------------------------------------------------------------------------
// The ZIP container
// ---------------------------------------------------------------------------

namespace {

uint16_t Read16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (p[1] << 8));
}

uint32_t Read32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

} // namespace

bool ZipReader::open(const uint8_t* data, size_t size) {
    data_ = data;
    size_ = size;
    entries_.clear();
    if (!data || size < 22) return false;

    // Find the end of central directory record, scanning backwards.
    size_t eocd = 0;
    bool found = false;
    size_t limit = size > 66000 ? size - 66000 : 0;
    for (size_t i = size - 22 + 1; i-- > limit;) {
        if (Read32(data + i) == 0x06054B50) {
            eocd = i;
            found = true;
            break;
        }
    }
    if (!found) return false;

    uint16_t entryCount = Read16(data + eocd + 10);
    uint32_t centralSize = Read32(data + eocd + 12);
    uint32_t centralOffset = Read32(data + eocd + 16);

    if (static_cast<uint64_t>(centralOffset) + centralSize > size) return false;

    size_t pos = centralOffset;
    for (uint16_t i = 0; i < entryCount; ++i) {
        if (pos + 46 > size) return false;
        if (Read32(data + pos) != 0x02014B50) return false;

        ZipEntry entry;
        entry.method = Read16(data + pos + 10);
        entry.crc32 = Read32(data + pos + 16);
        entry.compressedSize = Read32(data + pos + 20);
        entry.uncompressedSize = Read32(data + pos + 24);
        uint16_t nameLength = Read16(data + pos + 28);
        uint16_t extraLength = Read16(data + pos + 30);
        uint16_t commentLength = Read16(data + pos + 32);
        entry.localHeaderOffset = Read32(data + pos + 42);

        if (pos + 46 + nameLength > size) return false;
        entry.name.assign(reinterpret_cast<const char*>(data + pos + 46), nameLength);
        entries_.push_back(entry);

        pos += 46 + nameLength + extraLength + commentLength;
    }

    return !entries_.empty();
}

bool ZipReader::extract(const std::string& name, std::string& out) const {
    for (const ZipEntry& entry : entries_) {
        if (entry.name != name) continue;

        // The local header repeats the name and extra lengths, and the data
        // follows it.
        size_t pos = entry.localHeaderOffset;
        if (pos + 30 > size_) return false;
        if (Read32(data_ + pos) != 0x04034B50) return false;
        uint16_t nameLength = Read16(data_ + pos + 26);
        uint16_t extraLength = Read16(data_ + pos + 28);
        size_t dataStart = pos + 30 + nameLength + extraLength;
        if (dataStart + entry.compressedSize > size_) return false;

        const uint8_t* payload = data_ + dataStart;

        if (entry.method == 0) {
            out.assign(reinterpret_cast<const char*>(payload), entry.compressedSize);
        } else if (entry.method == 8) {
            if (!inflateRaw(payload, entry.compressedSize, out, entry.uncompressedSize)) {
                return false;
            }
        } else {
            return false;   // unsupported storage method
        }

        if (entry.crc32 != 0) {
            uint32_t actual = Crc32(reinterpret_cast<const uint8_t*>(out.data()), out.size());
            if (actual != entry.crc32) return false;
        }
        return true;
    }
    return false;
}

int ZipReader::extractAll(const std::string& destination,
                          const std::string& prefixFilter) const {
    int written = 0;
    std::error_code ec;
    std::filesystem::create_directories(destination, ec);

    for (const ZipEntry& entry : entries_) {
        // Only regular files, and only those below the filter.
        if (entry.name.empty() || entry.name.back() == '/') continue;
        if (!prefixFilter.empty() && entry.name.rfind(prefixFilter, 0) != 0) continue;

        std::string content;
        if (!extract(entry.name, content)) continue;

        std::filesystem::path relative(entry.name);
        std::filesystem::path target = std::filesystem::path(destination) / relative;

        // Refuse a path that escapes the destination.
        std::filesystem::path canonicalBase = std::filesystem::absolute(destination);
        for (const auto& part : relative) {
            if (part == "..") return -1;
        }

        std::filesystem::create_directories(target.parent_path(), ec);
        std::ofstream out(target, std::ios::binary | std::ios::trunc);
        if (!out) continue;
        out.write(content.data(), static_cast<std::streamsize>(content.size()));
        out.close();
        ++written;
    }
    return written;
}

} // namespace RawrXD
