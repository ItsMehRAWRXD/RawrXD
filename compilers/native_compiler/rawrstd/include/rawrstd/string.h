// rawrstd - growable byte string.

#ifndef RAWRSTD_STRING_H
#define RAWRSTD_STRING_H

#include "rawrstd/base.h"
#include "rawrstd/sys.h"

namespace rawrstd {

class String {
public:
    String() = default;
    String(const char* s) { assign(s); }
    String(const char* s, size_type n) { assign(s, n); }
    String(const String& other) { assign(other.data(), other.size()); }
    String(String&& other) noexcept { move_from(other); }

    ~String() { destroy(); }

    String& operator=(const String& other) {
        if (this != &other) assign(other.data(), other.size());
        return *this;
    }

    String& operator=(String&& other) noexcept {
        if (this != &other) {
            destroy();
            move_from(other);
        }
        return *this;
    }

    void assign(const char* s);
    void assign(const char* s, size_type n);
    void clear();

    const char* data() const { return data_ ? data_ : ""; }
    size_type size() const { return size_; }
    size_type capacity() const { return capacity_; }
    bool empty() const { return size_ == 0; }

    char operator[](size_type i) const { return data_[i]; }
    char& operator[](size_type i) { return data_[i]; }

    void push_back(char c);
    void append(const char* s, size_type n);
    void append(const String& other) { append(other.data(), other.size()); }
    void append(const char* s) { append(s, strlen_raw(s)); }
    void append_i64(int64 value);
    void append_u64(uint64 value);
    void append_hex_u64(uint64 value);
    void append_char_repeated(char c, size_type count);

    int compare(const String& other) const;
    bool operator==(const String& other) const { return compare(other) == 0; }
    bool operator!=(const String& other) const { return compare(other) != 0; }
    bool operator<(const String& other) const { return compare(other) < 0; }

    // Returns index of `needle` in [start, size), or npos.
    size_type find(const char* needle, size_type start = 0) const;

    // Returns the index of the character `c` in [start, size), or npos.
    size_type find(char c, size_type start = 0) const;

    const char* begin() const { return data_; }
    const char* end() const { return data_ + size_; }
    char* begin() { return data_; }
    char* end() { return data_ + size_; }

    // Removes the last character.
    void pop_back() {
        if (size_) {
            size_--;
            data_[size_] = '\0';
        }
    }

    String& operator+=(char c) {
        push_back(c);
        return *this;
    }

    String& operator+=(const char* text) {
        append(text);
        return *this;
    }

    // Returns the index of the last occurrence of `c`, or npos.
    size_type rfind(char c) const;

    // Returns the index of the first character not in `set`, or npos.
    size_type find_first_not_of(const char* set) const;

    // Returns the index of the first character in `set`, or npos.
    size_type find_first_of(const char* set) const;

    // Returns a substring.
    String substr(size_type pos, size_type count = npos) const;

    // Erases `count` characters starting at `pos`.
    void erase(size_type pos, size_type count = 1);

    char back() const { return size_ ? data_[size_ - 1] : '\0'; }
    char front() const { return size_ ? data_[0] : '\0'; }

    static constexpr size_type npos = ~size_type(0);

    // Splits on `sep`; returns the number of pieces written into `out`
    // (which must have room for `max_pieces` entries).
    size_type split(char sep, String* out, size_type max_pieces) const;

    bool ends_with(const char* suffix) const;
    bool starts_with(const char* prefix) const;

    void reserve(size_type n);

private:
    void destroy() {
        if (data_) heap_free(data_, capacity_ + 1);
        data_ = nullptr;
        size_ = 0;
        capacity_ = 0;
    }

    void move_from(String& other) {
        data_ = other.data_;
        size_ = other.size_;
        capacity_ = other.capacity_;
        other.data_ = nullptr;
        other.size_ = 0;
        other.capacity_ = 0;
    }

    char* data_ = nullptr;
    size_type size_ = 0;
    size_type capacity_ = 0;
};

// Concatenation helper.
inline String operator+(const String& a, const char* b) {
    String r;
    r.reserve(a.size() + (b ? rawrstd::strlen_raw(b) : 0));
    r.append(a);
    r.append(b);
    return r;
}

inline String operator+(const String& a, const String& b) {
    String r;
    r.reserve(a.size() + b.size());
    r.append(a);
    r.append(b);
    return r;
}

inline String operator+(const char* a, const String& b) {
    String r;
    r.assign(a);
    r.append(b);
    return r;
}

// Stream-style append used by the diagnostics engine.
// Note: size_type is 64-bit on Windows x64, so it shares the uint64 overload.
inline String& operator<<(String& s, const char* v) { s.append(v); return s; }
inline String& operator<<(String& s, const String& v) { s.append(v); return s; }
inline String& operator<<(String& s, char v) { s.push_back(v); return s; }
inline String& operator<<(String& s, int64 v) { s.append_i64(v); return s; }
inline String& operator<<(String& s, int v) { s.append_i64(v); return s; }
inline String& operator<<(String& s, uint64 v) { s.append_u64(v); return s; }
inline String& operator<<(String& s, uint32 v) { s.append_u64(v); return s; }
inline String& operator<<(String& s, bool v) { s.append(v ? "true" : "false"); return s; }

} // namespace rawrstd

#endif // RAWRSTD_STRING_H
