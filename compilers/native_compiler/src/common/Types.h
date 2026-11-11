// Common type aliases for the RawrXD native compiler.
//
// The compiler's own code is written against rawrstd (the dependency-free
// runtime), so the fixed-width integer types are pulled into the `rawr`
// namespace here rather than being re-declared in every header.

#ifndef RAWR_COMPILER_TYPES_H
#define RAWR_COMPILER_TYPES_H

#include "rawrstd/base.h"
#include "rawrstd/string.h"
#include "rawrstd/vector.h"

namespace rawr {

using rawrstd::int8;
using rawrstd::uint8;
using rawrstd::int16;
using rawrstd::uint16;
using rawrstd::int32;
using rawrstd::uint32;
using rawrstd::int64;
using rawrstd::uint64;
using rawrstd::size_type;
using rawrstd::size_t;
using rawrstd::String;
using rawrstd::Vector;
using rawrstd::min_of;
using rawrstd::max_of;
using rawrstd::abs_of;

} // namespace rawr

#endif // RAWR_COMPILER_TYPES_H
