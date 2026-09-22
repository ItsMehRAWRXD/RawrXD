// ============================================================================
// BinaryStream.hpp — Lightweight binary stream wrapper for GGUF parsing
// ============================================================================
#pragma once
#include <cstdint>
#include <cstddef>
#include <istream>
#include <streambuf>
#include <fstream>
#include <string>

namespace RawrXD {

enum class StreamStatus : uint8_t {
    Ok = 0,
    ReadError = 1,
    ReadCorruptData = 2,
    WriteError = 3,
    UnexpectedEnd = 4
};

class BinaryStream {
public:
    explicit BinaryStream(std::istream* s = nullptr) : stream_(s), status_(StreamStatus::Ok), swapBytes_(false) {}
    explicit BinaryStream(std::istream& s) : stream_(&s), status_(StreamStatus::Ok), swapBytes_(false) {}

    void setByteOrderLittleEndian() { swapBytes_ = false; }
    void setByteOrderBigEndian()    { swapBytes_ = true; }

    StreamStatus status() const { return status_; }
    void setStatus(StreamStatus s) { status_ = s; }
    bool atEnd() const {
        if (!stream_) return true;
        return stream_->eof() || stream_->fail();
    }

    int readRawData(char* buf, int len) {
        if (!stream_ || len < 0) return -1;
        stream_->read(buf, len);
        int got = static_cast<int>(stream_->gcount());
        if (got != len) status_ = StreamStatus::UnexpectedEnd;
        return got;
    }

    void skipRawData(int len) {
        if (!stream_ || len < 0) return;
        stream_->seekg(len, std::ios::cur);
        if (stream_->fail()) status_ = StreamStatus::ReadError;
    }

    // Scalar extractors
    BinaryStream& operator>>(uint8_t&  v) { read(v); return *this; }
    BinaryStream& operator>>(int8_t&   v) { read(v); return *this; }
    BinaryStream& operator>>(uint16_t& v) { read(v); if (swapBytes_) v = swap16(v); return *this; }
    BinaryStream& operator>>(int16_t&  v) { read(v); if (swapBytes_) v = static_cast<int16_t>(swap16(static_cast<uint16_t>(v))); return *this; }
    BinaryStream& operator>>(uint32_t& v) { read(v); if (swapBytes_) v = swap32(v); return *this; }
    BinaryStream& operator>>(int32_t&  v) { read(v); if (swapBytes_) v = static_cast<int32_t>(swap32(static_cast<uint32_t>(v))); return *this; }
    BinaryStream& operator>>(uint64_t& v) { read(v); if (swapBytes_) v = swap64(v); return *this; }
    BinaryStream& operator>>(int64_t&  v) { read(v); if (swapBytes_) v = static_cast<int64_t>(swap64(static_cast<uint64_t>(v))); return *this; }
    BinaryStream& operator>>(float&     v) { uint32_t u; read(u); if (swapBytes_) u = swap32(u); std::memcpy(&v, &u, sizeof(v)); return *this; }
    BinaryStream& operator>>(bool&      v) { uint8_t u; read(u); v = (u != 0); return *this; }

private:
    std::istream* stream_;
    StreamStatus  status_;
    bool          swapBytes_;

    template <typename T>
    void read(T& v) {
        if (!stream_) { status_ = StreamStatus::ReadError; return; }
        stream_->read(reinterpret_cast<char*>(&v), sizeof(v));
        if (static_cast<size_t>(stream_->gcount()) != sizeof(v)) status_ = StreamStatus::UnexpectedEnd;
    }

    static uint16_t swap16(uint16_t x) { return static_cast<uint16_t>((x >> 8) | (x << 8)); }
    static uint32_t swap32(uint32_t x) { return (x >> 24) | ((x >> 8) & 0xFF00u) | ((x << 8) & 0xFF0000u) | (x << 24); }
    static uint64_t swap64(uint64_t x) {
        return (x >> 56) | ((x >> 40) & 0xFF00ull) | ((x >> 24) & 0xFF0000ull) | ((x >> 8) & 0xFF000000ull) |
               ((x << 8) & 0xFF00000000ull) | ((x << 24) & 0xFF0000000000ull) | ((x << 40) & 0xFF000000000000ull) | (x << 56);
    }
};

class NativeFile {
public:
    NativeFile() = default;
    explicit NativeFile(const std::string& path) : path_(path) {}

    bool exists() const {
        if (FILE* f = nullptr; fopen_s(&f, path_.c_str(), "rb") == 0 && f) {
            fclose(f);
            return true;
        }
        return false;
    }

    bool open() {
        file_.open(path_, std::ios::binary);
        return file_.is_open();
    }

    bool isOpen() const { return file_.is_open(); }
    void close() { file_.close(); }

    std::istream* getStream() { return &file_; }

    int64_t size() const {
        if (!file_.is_open()) return -1;
        auto cur = file_.tellg();
        file_.seekg(0, std::ios::end);
        int64_t sz = static_cast<int64_t>(file_.tellg());
        file_.seekg(cur, std::ios::beg);
        return sz;
    }

private:
    std::string path_;
    mutable std::ifstream file_;
};

} // namespace RawrXD
