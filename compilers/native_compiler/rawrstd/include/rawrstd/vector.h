// rawrstd - growable contiguous container.

#ifndef RAWRSTD_VECTOR_H
#define RAWRSTD_VECTOR_H

#include "rawrstd/base.h"
#include "rawrstd/sys.h"

namespace rawrstd {

// Minimal allocator contract. The compiler only ever needs raw memory.
template <typename T>
struct DefaultAllocator {
    using value_type = T;

    T* allocate(size_type n) {
        return static_cast<T*>(heap_alloc(n * sizeof(T)));
    }

    void deallocate(T* p, size_type n) {
        heap_free(p, n * sizeof(T));
    }
};

template <typename T, typename Alloc = DefaultAllocator<T>>
class Vector {
public:
    using value_type = T;

    Vector() = default;

    // Fills the vector with `n` copies of `value`.
    Vector(size_type n, const T& value) {
        if (n == 0) return;
        reserve(n);
        for (size_type i = 0; i < n; ++i) new (data_ + i) T(value);
        size_ = n;
    }

    Vector(const Vector& other) { copy_from(other); }
    Vector(Vector&& other) noexcept { move_from(other); }

    ~Vector() { destroy(); }

    Vector& operator=(const Vector& other) {
        if (this != &other) {
            destroy();
            copy_from(other);
        }
        return *this;
    }

    Vector& operator=(Vector&& other) noexcept {
        if (this != &other) {
            destroy();
            move_from(other);
        }
        return *this;
    }

    void push_back(const T& value) {
        ensure_capacity(size_ + 1);
        new (data_ + size_) T(value);
        ++size_;
    }

    void push_back(T&& value) {
        ensure_capacity(size_ + 1);
        new (data_ + size_) T(static_cast<T&&>(value));
        ++size_;
    }

    template <typename... Args>
    T& emplace_back(Args&&... args) {
        ensure_capacity(size_ + 1);
        new (data_ + size_) T(static_cast<Args&&>(args)...);
        ++size_;
        return data_[size_ - 1];
    }

    void pop_back() {
        if (size_ > 0) {
            data_[size_ - 1].~T();
            --size_;
        }
    }

    void clear() {
        for (size_type i = 0; i < size_; ++i) data_[i].~T();
        size_ = 0;
    }

    void reserve(size_type n) {
        if (n <= capacity_) return;
        T* new_data = alloc_.allocate(n);
        for (size_type i = 0; i < size_; ++i) {
            new (new_data + i) T(static_cast<T&&>(data_[i]));
            data_[i].~T();
        }
        if (data_) alloc_.deallocate(data_, capacity_);
        data_ = new_data;
        capacity_ = n;
    }
    void resize(size_type n) {
        if (n < size_) {
            for (size_type i = n; i < size_; ++i) data_[i].~T();
            size_ = n;
        } else if (n > size_) {
            reserve(n);
            for (size_type i = size_; i < n; ++i) new (data_ + i) T();
            size_ = n;
        }
    }

    T& operator[](size_type i) { return data_[i]; }
    const T& operator[](size_type i) const { return data_[i]; }
    T& back() { return data_[size_ - 1]; }
    const T& back() const { return data_[size_ - 1]; }
    T* data() { return data_; }
    const T* data() const { return data_; }
    size_type size() const { return size_; }
    size_type capacity() const { return capacity_; }
    bool empty() const { return size_ == 0; }

    T* begin() { return data_; }
    T* end() { return data_ + size_; }
    const T* begin() const { return data_; }
    const T* end() const { return data_ + size_; }

    void swap(Vector& other) {
        T* d = data_; size_type s = size_; size_type c = capacity_;
        data_ = other.data_; size_ = other.size_; capacity_ = other.capacity_;
        other.data_ = d; other.size_ = s; other.capacity_ = c;
    }

private:
    void destroy() {
        for (size_type i = 0; i < size_; ++i) data_[i].~T();
        if (data_) alloc_.deallocate(data_, capacity_);
        data_ = nullptr;
        size_ = 0;
        capacity_ = 0;
    }

    void copy_from(const Vector& other) {
        if (other.size_ == 0) return;
        reserve(other.size_);
        for (size_type i = 0; i < other.size_; ++i) new (data_ + i) T(other.data_[i]);
        size_ = other.size_;
    }

    void move_from(Vector& other) {
        data_ = other.data_; size_ = other.size_; capacity_ = other.capacity_;
        other.data_ = nullptr; other.size_ = 0; other.capacity_ = 0;
    }

    void ensure_capacity(size_type n) {
        if (n <= capacity_) return;
        size_type new_cap = capacity_ ? capacity_ * 2 : 8;
        if (new_cap < n) new_cap = n;
        reserve(new_cap);
    }

    T* data_ = nullptr;
    size_type size_ = 0;
    size_type capacity_ = 0;
    Alloc alloc_;
};

} // namespace rawrstd

#endif // RAWRSTD_VECTOR_H
