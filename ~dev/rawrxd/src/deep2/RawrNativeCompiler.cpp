#include "RawrNativeCompiler.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstring>

namespace Deep2 {

RawrNativeTrampoline::~RawrNativeTrampoline() { reset(); }

RawrNativeTrampoline::RawrNativeTrampoline(RawrNativeTrampoline&& other) noexcept
    : allocation_(other.allocation_), allocationBytes_(other.allocationBytes_), entry_(other.entry_) {
    other.allocation_ = nullptr;
    other.allocationBytes_ = 0;
    other.entry_ = nullptr;
}

RawrNativeTrampoline& RawrNativeTrampoline::operator=(RawrNativeTrampoline&& other) noexcept {
    if (this == &other)
        return *this;
    reset();
    allocation_ = other.allocation_;
    allocationBytes_ = other.allocationBytes_;
    entry_ = other.entry_;
    other.allocation_ = nullptr;
    other.allocationBytes_ = 0;
    other.entry_ = nullptr;
    return *this;
}

bool RawrNativeTrampoline::compileJump(void* target) noexcept {
    reset();
    if (!target)
        return false;

    constexpr std::size_t codeBytes = 12;
    void* code = VirtualAlloc(nullptr, codeBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!code)
        return false;

    auto* bytes = static_cast<std::uint8_t*>(code);
    bytes[0] = 0x48;
    bytes[1] = 0xB8;
    const auto address = reinterpret_cast<std::uintptr_t>(target);
    std::memcpy(bytes + 2, &address, sizeof(address));
    bytes[10] = 0xFF;
    bytes[11] = 0xE0;

    DWORD oldProtection = 0;
    if (!VirtualProtect(code, codeBytes, PAGE_EXECUTE_READ, &oldProtection) ||
        !FlushInstructionCache(GetCurrentProcess(), code, codeBytes)) {
        VirtualFree(code, 0, MEM_RELEASE);
        return false;
    }
    allocation_ = code;
    allocationBytes_ = codeBytes;
    entry_ = code;
    return true;
}

void RawrNativeTrampoline::reset() noexcept {
    if (allocation_)
        VirtualFree(allocation_, 0, MEM_RELEASE);
    allocation_ = nullptr;
    allocationBytes_ = 0;
    entry_ = nullptr;
}

}
