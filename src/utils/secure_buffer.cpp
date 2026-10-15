// ============================================================================
// Platform feature macros must be visible before the first standard header.
// ============================================================================
#ifndef _CRT_SECURE_NO_WARNINGS
#  define _CRT_SECURE_NO_WARNINGS
#endif

#include "secure_buffer.h"

#include <exception>

#ifdef _WIN32
#  include <bcrypt.h>
#  pragma comment(lib, "bcrypt.lib")
#else
#  include <fstream>
#endif

namespace RawrXD {
namespace Security {

void secureZero(void* ptr, size_t len) noexcept
{
    // Writes through a volatile pointer so the optimizer cannot treat the
    // buffer as dead and skip the clear (a known C++ pitfall that leaves
    // secrets/weights recoverable from freed memory).
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    for (size_t i = 0; i < len; ++i) p[i] = 0u;
}

bool constantTimeEqual(const void* a, const void* b, size_t len) noexcept
{
    if (!a || !b) return false;
    const auto* pa = static_cast<const unsigned char*>(a);
    const auto* pb = static_cast<const unsigned char*>(b);
    unsigned char diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= static_cast<unsigned char>(pa[i] ^ pb[i]);
    }
    return diff == 0;
}

bool secureRandomBytes(void* ptr, size_t len) noexcept
{
    if (!ptr || len == 0) return false;

#ifdef _WIN32
    // BCryptGenRandom is the Windows CSPRNG (CNG) - no seeding, no user-mode
    // global state, and not affected by the legacy C rand() pitfalls.
    NTSTATUS status = ::BCryptGenRandom(nullptr,           // use the system RNG
                                        static_cast<PUCHAR>(ptr),
                                        static_cast<ULONG>(len),
                                        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return status >= 0;   // BCRYPT_SUCCESS
#else
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (!urandom) return false;
    urandom.read(static_cast<char*>(ptr), static_cast<std::streamsize>(len));
    return static_cast<size_t>(urandom.gcount()) == len;
#endif
}

} // namespace Security
} // namespace RawrXD