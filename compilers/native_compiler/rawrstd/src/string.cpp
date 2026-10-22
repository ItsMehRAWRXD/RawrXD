// rawrstd - String implementation.

#include "rawrstd/string.h"

namespace rawrstd {

void String::assign(const char* s) {
    assign(s, s ? strlen_raw(s) : 0);
}

void String::assign(const char* s, size_type n) {
    clear();
    if (n == 0) return;
    reserve(n);
    memcpy_raw(data_, s, n);
    data_[n] = '\0';
    size_ = n;
}

void String::clear() {
    size_ = 0;
    if (data_) data_[0] = '\0';
}

void String::reserve(size_type n) {
    if (n + 1 <= capacity_) return;
    size_type new_cap = capacity_ ? capacity_ * 2 : 32;
    while (new_cap < n + 1) new_cap *= 2;
    char* new_data = static_cast<char*>(heap_alloc(new_cap));
    if (!new_data) return;
    if (data_) {
        memcpy_raw(new_data, data_, size_);
        heap_free(data_, capacity_ + 1);
    }
    data_ = new_data;
    capacity_ = new_cap;
}

void String::push_back(char c) {
    reserve(size_ + 1);
    data_[size_++] = c;
    data_[size_] = '\0';
}

void String::append(const char* s, size_type n) {
    if (n == 0) return;
    reserve(size_ + n);
    memcpy_raw(data_ + size_, s, n);
    size_ += n;
    data_[size_] = '\0';
}

void String::append_i64(int64 value) {
    char tmp[24];
    size_type n = format_i64(tmp, value);
    append(tmp, n);
}

void String::append_u64(uint64 value) {
    char tmp[24];
    size_type n = format_u64(tmp, value);
    append(tmp, n);
}

void String::append_hex_u64(uint64 value) {
    char tmp[24];
    size_type n = format_hex_u64(tmp, value);
    append(tmp, n);
}

void String::append_char_repeated(char c, size_type count) {
    reserve(size_ + count);
    for (size_type i = 0; i < count; ++i) data_[size_ + i] = c;
    size_ += count;
    data_[size_] = '\0';
}

int String::compare(const String& other) const {
    size_type n = min_of(size_, other.size_);
    if (n > 0) {
        int c = memcmp_raw(data_, other.data_, n);
        if (c != 0) return c;
    }
    if (size_ == other.size_) return 0;
    return size_ < other.size_ ? -1 : 1;
}

size_type String::find(const char* needle, size_type start) const {
    size_type n = strlen_raw(needle);
    if (n == 0) return start <= size_ ? start : npos;
    if (n > size_) return npos;
    for (size_type i = start; i + n <= size_; ++i) {
        if (memcmp_raw(data_ + i, needle, n) == 0) return i;
    }
    return npos;
}

size_type String::split(char sep, String* out, size_type max_pieces) const {
    size_type count = 0;
    size_type start = 0;
    for (size_type i = 0; i <= size_; ++i) {
        if (i == size_ || data_[i] == sep) {
            if (count >= max_pieces) break;
            out[count].assign(data_ + start, i - start);
            ++count;
            start = i + 1;
        }
    }
    return count;
}

bool String::ends_with(const char* suffix) const {
    size_type n = strlen_raw(suffix);
    if (n > size_) return false;
    return memcmp_raw(data_ + size_ - n, suffix, n) == 0;
}

bool String::starts_with(const char* prefix) const {
    size_type n = strlen_raw(prefix);
    if (n > size_) return false;
    return memcmp_raw(data_, prefix, n) == 0;
}


size_type String::rfind(char c) const {
    for (size_type i = size_; i > 0; --i) {
        if (data_[i - 1] == c) return i - 1;
    }
    return npos;
}

size_type String::find_first_not_of(const char* set) const {
    for (size_type i = 0; i < size_; ++i) {
        bool in = false;
        for (const char* p = set; *p; ++p) {
            if (data_[i] == *p) { in = true; break; }
        }
        if (!in) return i;
    }
    return npos;
}

size_type String::find_first_of(const char* set) const {
    for (size_type i = 0; i < size_; ++i) {
        for (const char* p = set; *p; ++p) {
            if (data_[i] == *p) return i;
        }
    }
    return npos;
}

String String::substr(size_type pos, size_type count) const {
    if (pos >= size_) return String();
    size_type n = size_ - pos;
    if (count < n) n = count;
    return String(data_ + pos, n);
}

void String::erase(size_type pos, size_type count) {
    if (pos >= size_) return;
    if (count > size_ - pos) count = size_ - pos;
    for (size_type i = pos; i + count < size_; ++i) {
        data_[i] = data_[i + count];
    }
    size_ -= count;
    data_[size_] = '\0';
}

size_type String::find(char c, size_type start) const {
    for (size_type i = start; i < size_; ++i) {
        if (data_[i] == c) return i;
    }
    return npos;
}
} // namespace rawrstd
