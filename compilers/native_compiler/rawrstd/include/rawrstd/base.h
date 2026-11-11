// rawrstd - dependency-free foundation for the RawrXD native compiler.
//
// Deliberately does NOT include any C runtime header. The RawrXD compiler
// binary must be able to run on a machine with no MSVC/UCRT installed, so it
// cannot depend on <cstdio>, <cstring>, <new>, or the MSVC STL.
//
// Everything here is implemented on top of a thin Win32 syscall layer
// (see rawrstd/sys.h).

#ifndef RAWRSTD_BASE_H
#define RAWRSTD_BASE_H

// Placement new comes from the language header. It is a declaration
// only, so it does not pull the C runtime into the build.
#include <new>

namespace rawrstd {

// Freestanding size_t. We cannot include <cstddef> because that drags in the
// CRT's <vcruntime.h>. On Windows x64, size_t is an unsigned 64-bit integer.
using size_t = unsigned long long;

using int8 = signed char;
using uint8 = unsigned char;
using int16 = signed short;
using uint16 = unsigned short;
using int32 = int;
using uint32 = unsigned int;
using int64 = long long;
using uint64 = unsigned long long;
using size_type = size_t;
using nullptr_t = decltype(nullptr);

template <typename T>
constexpr T min_of(T a, T b) { return a < b ? a : b; }

template <typename T>
constexpr T max_of(T a, T b) { return a > b ? a : b; }

template <typename T>
constexpr T abs_of(T v) { return v < 0 ? -v : v; }

} // namespace rawrstd

#endif // RAWRSTD_BASE_H
