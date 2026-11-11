#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <limits>
#include <string>
#include <vector>

namespace rawrxd::rom {

constexpr uint64_t kAlignment = 64ull * 1024ull;
constexpr uint32_t kVersion = 1;

struct TensorInput {
    std::string name;
    uint32_t dtype = 0;
    std::vector<uint64_t> dims;
    std::vector<uint8_t> bytes;
    uint32_t flags = 0;
};

// A source-backed tensor used by the GGUF cartridge writer.  The callback is
// invoked once per tensor and may materialize only that tensor, keeping peak
// host memory bounded while the ROM file is assembled.
struct TensorSource {
    std::string name;
    uint32_t dtype = 0;
    std::vector<uint64_t> dims;
    uint64_t bytes = 0;
    uint32_t flags = 0;
    std::function<bool(std::vector<uint8_t>&)> read;
    // Optional bounded reader for tensors too large to materialize. The
    // callback fills [offset, offset+bytes) and is invoked in small chunks.
    std::function<bool(uint64_t offset, uint8_t* dst, size_t bytes)> readChunk;
};

struct TensorRecord {
    std::string name;
    uint32_t dtype = 0;
    std::vector<uint64_t> dims;
    uint64_t offset = 0;
    uint64_t bytes = 0;
    uint64_t paddedBytes = 0;
    uint32_t flags = 0;
};

struct Header {
    char magic[8] = {'R','X','R','O','M','0','0','1'};
    uint32_t version = kVersion;
    uint32_t alignment = static_cast<uint32_t>(kAlignment);
    uint64_t tableOffset = 0;
    uint64_t dataOffset = 0;
    uint64_t tensorCount = 0;
    uint64_t fileBytes = 0;
    uint64_t payloadHash = 0;
};

inline bool AlignUp(uint64_t value, uint64_t alignment, uint64_t& out) {
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) return false;
    const uint64_t mask = alignment - 1;
    if (value > std::numeric_limits<uint64_t>::max() - mask) return false;
    out = (value + mask) & ~mask;
    return true;
}

inline uint64_t HashBytes(const uint8_t* data, size_t size, uint64_t seed = 1469598103934665603ull) {
    uint64_t h = seed;
    for (size_t i = 0; i < size; ++i) {
        h ^= data[i];
        h *= 1099511628211ull;
    }
    return h;
}

inline bool WriteU32(std::ostream& out, uint32_t v) { return !!out.write(reinterpret_cast<const char*>(&v), sizeof(v)); }
inline bool WriteU64(std::ostream& out, uint64_t v) { return !!out.write(reinterpret_cast<const char*>(&v), sizeof(v)); }

inline bool ReadU32(std::ifstream& in, uint32_t& v) { return !!in.read(reinterpret_cast<char*>(&v), sizeof(v)); }
inline bool ReadU64(std::ifstream& in, uint64_t& v) { return !!in.read(reinterpret_cast<char*>(&v), sizeof(v)); }

inline bool Write(const std::string& path, const std::vector<TensorInput>& inputs, std::string& error) {
    Header header;
    header.tensorCount = inputs.size();
    std::vector<TensorRecord> records;
    records.reserve(inputs.size());

    uint64_t tableBytes = sizeof(Header);
    for (const auto& input : inputs) {
        if (input.name.size() > std::numeric_limits<uint32_t>::max() || input.dims.size() > 8) {
            error = "tensor metadata too large"; return false;
        }
        uint64_t next = 0;
        if (input.bytes.size() > std::numeric_limits<uint64_t>::max() - tableBytes) {
            error = "ROM size overflow"; return false;
        }
        tableBytes += sizeof(uint32_t) * 3 + sizeof(uint64_t) * (2 + input.dims.size()) + input.name.size();
        (void)next;
    }
    if (!AlignUp(tableBytes, kAlignment, header.dataOffset)) { error = "header alignment overflow"; return false; }
    header.tableOffset = sizeof(Header);

    uint64_t cursor = header.dataOffset;
    uint64_t hash = 1469598103934665603ull;
    for (const auto& input : inputs) {
        TensorRecord record;
        record.name = input.name;
        record.dtype = input.dtype;
        record.dims = input.dims;
        record.bytes = input.bytes.size();
        record.flags = input.flags;
        if (!AlignUp(record.bytes, kAlignment, record.paddedBytes) ||
            cursor > std::numeric_limits<uint64_t>::max() - record.paddedBytes) {
            error = "payload alignment overflow"; return false;
        }
        record.offset = cursor;
        cursor += record.paddedBytes;
        hash = HashBytes(input.bytes.data(), input.bytes.size(), hash);
        records.push_back(std::move(record));
    }
    header.fileBytes = cursor;
    header.payloadHash = hash;

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) { error = "cannot create ROM"; return false; }
    out.write(reinterpret_cast<const char*>(&header), sizeof(header));
    for (const auto& record : records) {
        if (!WriteU32(out, static_cast<uint32_t>(record.name.size())) ||
            !WriteU32(out, record.dtype) || !WriteU32(out, record.flags) ||
            !WriteU32(out, static_cast<uint32_t>(record.dims.size())) ||
            !out.write(record.name.data(), static_cast<std::streamsize>(record.name.size())) ||
            !WriteU64(out, record.offset) || !WriteU64(out, record.bytes) ||
            !WriteU64(out, record.paddedBytes)) { error = "cannot write ROM table"; return false; }
        for (uint64_t dim : record.dims) if (!WriteU64(out, dim)) { error = "cannot write ROM dimensions"; return false; }
    }
    const std::streamoff now = out.tellp();
    if (now < 0 || static_cast<uint64_t>(now) > header.dataOffset) { error = "ROM table exceeds data offset"; return false; }
    std::vector<uint8_t> zero(static_cast<size_t>(header.dataOffset - static_cast<uint64_t>(now)), 0);
    out.write(reinterpret_cast<const char*>(zero.data()), static_cast<std::streamsize>(zero.size()));
    for (size_t inputIndex = 0; inputIndex < inputs.size(); ++inputIndex) {
        const auto& input = inputs[inputIndex];
        out.write(reinterpret_cast<const char*>(input.bytes.data()), static_cast<std::streamsize>(input.bytes.size()));
        std::vector<uint8_t> padding(static_cast<size_t>(records[inputIndex].paddedBytes - input.bytes.size()), 0);
        out.write(reinterpret_cast<const char*>(padding.data()), static_cast<std::streamsize>(padding.size()));
    }
    if (!out || static_cast<uint64_t>(out.tellp()) != header.fileBytes) { error = "ROM write size mismatch"; return false; }
    return true;
}

inline bool WriteStream(const std::string& path, const std::vector<TensorSource>& sources, std::string& error) {
    Header header;
    header.tensorCount = sources.size();
    std::vector<TensorRecord> records;
    records.reserve(sources.size());
    uint64_t tableBytes = sizeof(Header);
    for (const auto& source : sources) {
        if (source.name.size() > std::numeric_limits<uint32_t>::max() || source.dims.size() > 8 ||
            (!source.read && !source.readChunk)) {
            error = "invalid tensor source"; return false;
        }
        if (tableBytes > std::numeric_limits<uint64_t>::max() -
                (sizeof(uint32_t) * 3 + sizeof(uint64_t) * (2 + source.dims.size()) + source.name.size())) {
            error = "ROM table overflow"; return false;
        }
        tableBytes += sizeof(uint32_t) * 3 + sizeof(uint64_t) * (2 + source.dims.size()) + source.name.size();
    }
    if (!AlignUp(tableBytes, kAlignment, header.dataOffset)) { error = "header alignment overflow"; return false; }
    header.tableOffset = sizeof(Header);

    uint64_t cursor = header.dataOffset;
    for (const auto& source : sources) {
        TensorRecord record;
        record.name = source.name;
        record.dtype = source.dtype;
        record.dims = source.dims;
        record.bytes = source.bytes;
        record.flags = source.flags;
        if (!AlignUp(record.bytes, kAlignment, record.paddedBytes) ||
            cursor > std::numeric_limits<uint64_t>::max() - record.paddedBytes) {
            error = "payload alignment overflow"; return false;
        }
        record.offset = cursor;
        cursor += record.paddedBytes;
        records.push_back(std::move(record));
    }
    header.fileBytes = cursor;

    std::fstream out(path, std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc);
    if (!out) { error = "cannot create ROM"; return false; }
    out.write(reinterpret_cast<const char*>(&header), sizeof(header));
    for (const auto& record : records) {
        if (!WriteU32(out, static_cast<uint32_t>(record.name.size())) ||
            !WriteU32(out, record.dtype) || !WriteU32(out, record.flags) ||
            !WriteU32(out, static_cast<uint32_t>(record.dims.size())) ||
            !out.write(record.name.data(), static_cast<std::streamsize>(record.name.size())) ||
            !WriteU64(out, record.offset) || !WriteU64(out, record.bytes) ||
            !WriteU64(out, record.paddedBytes)) { error = "cannot write ROM table"; return false; }
        for (uint64_t dim : record.dims) if (!WriteU64(out, dim)) { error = "cannot write ROM dimensions"; return false; }
    }
    const std::streamoff tableEnd = out.tellp();
    if (tableEnd < 0 || static_cast<uint64_t>(tableEnd) > header.dataOffset) { error = "ROM table exceeds data offset"; return false; }
    std::vector<uint8_t> zero(static_cast<size_t>(header.dataOffset - static_cast<uint64_t>(tableEnd)), 0);
    out.write(reinterpret_cast<const char*>(zero.data()), static_cast<std::streamsize>(zero.size()));

    uint64_t hash = 1469598103934665603ull;
    const size_t chunkBytes = 1u << 20;
    std::vector<uint8_t> chunk(chunkBytes);
    std::vector<uint8_t> padding(1u << 16, 0);
    for (size_t i = 0; i < sources.size(); ++i) {
        uint64_t remaining = records[i].bytes;
        uint64_t offset = 0;
        while (remaining != 0) {
            const size_t want = static_cast<size_t>(std::min<uint64_t>(remaining, chunk.size()));
            bool ok = false;
            if (sources[i].readChunk) {
                ok = sources[i].readChunk(offset, chunk.data(), want);
            } else {
                std::vector<uint8_t> payload;
                ok = sources[i].read(payload) && payload.size() == records[i].bytes &&
                     offset == 0 && want == payload.size();
                if (ok) std::memcpy(chunk.data(), payload.data(), want);
            }
            if (!ok) { error = "tensor source read/size mismatch"; return false; }
            hash = HashBytes(chunk.data(), want, hash);
            out.write(reinterpret_cast<const char*>(chunk.data()), static_cast<std::streamsize>(want));
            if (!out) { error = "ROM payload write failed"; return false; }
            offset += want;
            remaining -= want;
        }
        uint64_t padRemaining = records[i].paddedBytes - records[i].bytes;
        while (padRemaining != 0) {
            const size_t want = static_cast<size_t>(std::min<uint64_t>(padRemaining, padding.size()));
            out.write(reinterpret_cast<const char*>(padding.data()), static_cast<std::streamsize>(want));
            padRemaining -= want;
        }
        if (!out) { error = "ROM payload write failed"; return false; }
    }
    if (static_cast<uint64_t>(out.tellp()) != header.fileBytes) { error = "ROM write size mismatch"; return false; }
    header.payloadHash = hash;
    out.seekp(0, std::ios::beg);
    out.write(reinterpret_cast<const char*>(&header), sizeof(header));
    if (!out) { error = "ROM header finalization failed"; return false; }
    return true;
}

inline bool Read(const std::string& path, std::vector<TensorRecord>& records, Header& header, std::string& error) {
    std::ifstream in(path, std::ios::binary);
    if (!in || !in.read(reinterpret_cast<char*>(&header), sizeof(header))) { error = "cannot read ROM header"; return false; }
    const char expected[8] = {'R','X','R','O','M','0','0','1'};
    if (std::memcmp(header.magic, expected, sizeof(expected)) != 0 || header.version != kVersion || header.alignment != kAlignment) { error = "invalid ROM signature or alignment"; return false; }
    if (header.tensorCount > 1000000 || header.tableOffset != sizeof(Header) ||
        header.dataOffset < sizeof(Header) || header.dataOffset % header.alignment != 0 ||
        header.fileBytes < header.dataOffset) { error = "invalid ROM bounds"; return false; }
    in.seekg(0, std::ios::end);
    const std::streamoff physicalBytes = in.tellg();
    if (physicalBytes < 0 || static_cast<uint64_t>(physicalBytes) != header.fileBytes) {
        error = "ROM physical size does not match header"; return false;
    }
    in.seekg(static_cast<std::streamoff>(header.tableOffset), std::ios::beg);
    records.clear(); records.reserve(static_cast<size_t>(header.tensorCount));
    for (uint64_t i = 0; i < header.tensorCount; ++i) {
        uint32_t nameLen=0, dtype=0, flags=0, rank=0;
        TensorRecord r;
        if (!ReadU32(in,nameLen) || !ReadU32(in,dtype) || !ReadU32(in,flags) || !ReadU32(in,rank) || nameLen > 1u<<20 || rank > 8) { error = "invalid ROM tensor table"; return false; }
        r.name.resize(nameLen); if (!in.read(r.name.data(), nameLen) || !ReadU64(in,r.offset) || !ReadU64(in,r.bytes) || !ReadU64(in,r.paddedBytes)) { error = "truncated ROM tensor table"; return false; }
        r.dtype=dtype; r.flags=flags; r.dims.resize(rank); for (auto& d:r.dims) if(!ReadU64(in,d)){error="truncated ROM dimensions";return false;}
        if (r.offset % header.alignment != 0 || r.offset < header.dataOffset ||
            r.paddedBytes < r.bytes || r.paddedBytes % header.alignment != 0 ||
            r.offset > header.fileBytes || r.paddedBytes > header.fileBytes-r.offset) { error="ROM tensor bounds/alignment failure"; return false; }
        records.push_back(std::move(r));
    }

    const std::streamoff tableEnd = in.tellg();
    if (tableEnd < 0 || static_cast<uint64_t>(tableEnd) > header.dataOffset) {
        error = "ROM tensor table overlaps payload area"; return false;
    }

    // Validate that records form disjoint aligned extents.  This catches a
    // malicious or partially-written page table before any payload is used.
    std::vector<size_t> order(records.size());
    for (size_t i = 0; i < order.size(); ++i) order[i] = i;
    std::sort(order.begin(), order.end(), [&records](size_t a, size_t b) {
        return records[a].offset < records[b].offset;
    });
    uint64_t previousEnd = header.dataOffset;
    for (size_t index : order) {
        const auto& record = records[index];
        if (record.offset < previousEnd) {
            error = "ROM tensor extents overlap"; return false;
        }
        if (record.paddedBytes > std::numeric_limits<uint64_t>::max() - record.offset) {
            error = "ROM tensor extent overflow"; return false;
        }
        previousEnd = std::max(previousEnd, record.offset + record.paddedBytes);
    }

    // Verify the payload digest, not only the signature and page geometry.
    // The digest follows table order and excludes alignment padding.
    uint64_t payloadHash = 1469598103934665603ull;
    std::vector<uint8_t> buffer(1u << 20);
    for (const auto& record : records) {
        in.seekg(static_cast<std::streamoff>(record.offset), std::ios::beg);
        uint64_t remaining = record.bytes;
        while (remaining != 0) {
            const size_t chunk = static_cast<size_t>(std::min<uint64_t>(remaining, buffer.size()));
            if (!in.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(chunk))) {
                error = "truncated ROM payload"; return false;
            }
            payloadHash = HashBytes(buffer.data(), chunk, payloadHash);
            remaining -= chunk;
        }
    }
    if (payloadHash != header.payloadHash) {
        error = "ROM payload digest mismatch"; return false;
    }
    return true;
}

} // namespace rawrxd::rom
