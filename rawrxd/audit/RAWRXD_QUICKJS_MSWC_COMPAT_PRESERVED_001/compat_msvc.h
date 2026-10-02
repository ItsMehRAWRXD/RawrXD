/* QuickJS MSVC Compatibility Header
 * Defines GCC builtins and attributes for MSVC compilation.
 */
#ifndef COMPAT_MSVC_H
#define COMPAT_MSVC_H

#ifdef _MSC_VER
#include <intrin.h>
#include <stdint.h>

/* Drop all __attribute__ expansions */
#define __attribute__(...)

/* __builtin_expect */
#define __builtin_expect(x, y) (x)

/* __builtin_clz family */
static inline int __builtin_clz(unsigned int a)
{
    unsigned long index;
    return _BitScanReverse(&index, a) ? 31 - (int)index : 32;
}
static inline int __builtin_clzll(uint64_t a)
{
    unsigned long index;
#if defined(_WIN64)
    return _BitScanReverse64(&index, a) ? 63 - (int)index : 64;
#else
    if (_BitScanReverse(&index, (unsigned long)(a >> 32)))
        return 31 - (int)index;
    return _BitScanReverse(&index, (unsigned long)a) ? 63 - (int)index : 64;
#endif
}
static inline int __builtin_ctz(unsigned int a)
{
    unsigned long index;
    return _BitScanForward(&index, a) ? (int)index : 32;
}
static inline int __builtin_ctzll(uint64_t a)
{
    unsigned long index;
#if defined(_WIN64)
    return _BitScanForward64(&index, a) ? (int)index : 64;
#else
    if (_BitScanForward(&index, (unsigned long)a))
        return (int)index;
    return _BitScanForward(&index, (unsigned long)(a >> 32)) ? 32 + (int)index : 64;
#endif
}

/* __builtin_frame_address(0) */
static inline void *__builtin_frame_address(unsigned int level)
{
    if (level == 0) {
        return _AddressOfReturnAddress();
    }
    return (void *)0;
}

/* __maybe_unused */
#define __maybe_unused

/* Portable packed struct support */
#define PACKED_STRUCT_BEGIN __pragma(pack(push, 1))
#define PACKED_STRUCT_END   __pragma(pack(pop))
#define PACKED_ATTR

#else /* !_MSC_VER */
#define PACKED_STRUCT_BEGIN
#define PACKED_STRUCT_END
#define PACKED_ATTR __attribute__((packed))

#endif /* _MSC_VER */
#endif /* COMPAT_MSVC_H */
