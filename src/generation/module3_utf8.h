#pragma once
// =============================================================================
// Module 3: UTF-8 Streaming Sanitizer
// Handles partial multi-byte sequences split across token boundaries.
// Replaces invalid sequences with U+FFFD.
// No external dependencies beyond <vector>, <string>, <cstdint>.
// =============================================================================

#include <cstdint>
#include <string>
#include <vector>

class Utf8StreamingSanitizer {
public:
    Utf8StreamingSanitizer() : buffer_() {}

    // Feed raw token bytes. Returns valid UTF-8 string (may be empty
    // if bytes are incomplete and waiting for more data).
    std::string sanitize(const char* token) {
        if (token == nullptr || token[0] == '\0') {
            return std::string();
        }

        std::string raw(token);
        std::string result;
        result.reserve(raw.size());

        for (size_t i = 0; i < raw.size(); ++i) {
            buffer_.push_back(static_cast<uint8_t>(raw[i]));

            std::string flushed;
            if (tryFlush(flushed)) {
                result += flushed;
            }
        }
        return result;
    }

    // Call when generation is complete. Flushes any remaining
    // incomplete bytes as U+FFFD.
    std::string flush() {
        if (buffer_.empty()) {
            return std::string();
        }
        std::string result;
        for (size_t i = 0; i < buffer_.size(); ++i) {
            // U+FFFD in UTF-8: EF BF BD
            result += static_cast<char>(0xEF);
            result += static_cast<char>(0xBF);
            result += static_cast<char>(0xBD);
        }
        buffer_.clear();
        return result;
    }

    void reset() {
        buffer_.clear();
    }

private:
    std::vector<uint8_t> buffer_;

    // Returns number of bytes expected for a valid UTF-8 sequence
    // starting with the lead byte at buffer_[0].
    // Returns 0 for invalid lead bytes.
    static size_t expectedBytes(const std::vector<uint8_t>& buf) {
        if (buf.empty()) return 0;
        uint8_t lead = buf[0];
        if (lead < 0x80) return 1;        // ASCII
        if ((lead & 0xE0) == 0xC0) return 2;  // 2-byte sequence
        if ((lead & 0xF0) == 0xE0) return 3;  // 3-byte sequence
        if ((lead & 0xF8) == 0xF0) return 4;  // 4-byte sequence
        return 0;  // Invalid lead byte
    }

    // Validates a complete multi-byte UTF-8 sequence.
    static bool isValidSequence(const std::vector<uint8_t>& buf, size_t len) {
        // Check continuation bytes
        for (size_t i = 1; i < len; ++i) {
            if ((buf[i] & 0xC0) != 0x80) return false;
        }
        // Check for overlong encodings and surrogates
        if (len == 2) {
            if ((buf[0] & 0x1E) == 0) return false;  // Overlong
        } else if (len == 3) {
            if (buf[0] == 0xE0 && buf[1] < 0xA0) return false;  // Overlong
            if (buf[0] == 0xED && buf[1] >= 0xA0) return false; // Surrogate
        } else if (len == 4) {
            if (buf[0] == 0xF0 && buf[1] < 0x90) return false;  // Overlong
            if (buf[0] == 0xF4 && buf[1] >= 0x90) return false; // > U+10FFFF
        }
        return true;
    }

    // Attempts to flush a complete valid sequence from the buffer.
    // Returns true and fills 'out' if a sequence was flushed.
    // Returns false if waiting for more bytes, or replaces an
    // invalid lead byte.
    bool tryFlush(std::string& out) {
        size_t need = expectedBytes(buffer_);
        if (need == 0) {
            // Invalid lead byte — replace with U+FFFD
            out.clear();
            out += static_cast<char>(0xEF);
            out += static_cast<char>(0xBF);
            out += static_cast<char>(0xBD);
            buffer_.erase(buffer_.begin());
            return true;
        }
        if (buffer_.size() < need) {
            return false;  // Waiting for more bytes
        }
        if (isValidSequence(buffer_, need)) {
            out.assign(reinterpret_cast<const char*>(buffer_.data()), need);
            buffer_.erase(buffer_.begin(), buffer_.begin() + need);
            return true;
        }
        // Invalid sequence — replace lead byte
        out.clear();
        out += static_cast<char>(0xEF);
        out += static_cast<char>(0xBF);
        out += static_cast<char>(0xBD);
        buffer_.erase(buffer_.begin());
        return true;
    }
};