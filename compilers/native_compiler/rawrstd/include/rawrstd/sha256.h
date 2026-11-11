// SHA-256 for the RawrXD certification harness.
//
// The compiler must be able to hash the artifacts it produces so that a
// determinism check compares real content rather than a timestamp. This is
// a self-contained FIPS 180-4 implementation so the compiler keeps its
// "no external dependency" property.

#ifndef RAWRSTD_SHA256_H
#define RAWRSTD_SHA256_H

#include "rawrstd/base.h"
#include "rawrstd/string.h"

namespace rawrstd {

// Computes the SHA-256 digest of a buffer and writes it as 64 lowercase
// hex characters (no terminator) into `out`.
void sha256_hex(const void* data, size_type size, char* out);

// Convenience: hashes a file. Returns an empty string when the file
// cannot be read.
String sha256_file(const char* path);

} // namespace rawrstd

#endif // RAWRSTD_SHA256_H
