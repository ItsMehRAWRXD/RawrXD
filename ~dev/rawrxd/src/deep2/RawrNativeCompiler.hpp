#pragma once

#include <cstddef>
#include <cstdint>

namespace Deep2 {

class RawrNativeTrampoline {
public:
    RawrNativeTrampoline() = default;
    ~RawrNativeTrampoline();
    RawrNativeTrampoline(const RawrNativeTrampoline&) = delete;
    RawrNativeTrampoline& operator=(const RawrNativeTrampoline&) = delete;
    RawrNativeTrampoline(RawrNativeTrampoline&& other) noexcept;
    RawrNativeTrampoline& operator=(RawrNativeTrampoline&& other) noexcept;

    bool compileJump(void* target) noexcept;
    void reset() noexcept;
    void* entry() const noexcept { return entry_; }
    explicit operator bool() const noexcept { return entry_ != nullptr; }

private:
    void* allocation_ = nullptr;
    std::size_t allocationBytes_ = 0;
    void* entry_ = nullptr;
};

}
