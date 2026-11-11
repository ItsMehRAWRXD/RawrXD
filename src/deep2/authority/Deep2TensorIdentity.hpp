#pragma once
// RawrXD source-only tensor identity adapter. No third-party dependencies.
// Distinguishes the three existing TensorInfo ABIs without importing their headers.
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>

namespace Deep2::Authority {
enum class SourceABI { LegacyGGUF, EngineCommon, Deep2Reader };
enum class TypeDialect { CanonicalGGML, LegacyGGUFHeader, EngineCommonHeader };
struct TensorDescriptor {
    std::string name;
    std::vector<std::uint64_t> dimensions;
    std::uint32_t canonical_type = 0;
    std::uint64_t offset = 0;
    std::uint64_t bytes = 0;
    SourceABI origin = SourceABI::Deep2Reader;
};

// Old enum numeric values in include/gguf_loader.h and engine/common_types.h
// differ from the canonical GGML IDs. Unknown and conflicting codes fail closed.
inline std::optional<std::uint32_t> canonical_type(std::uint32_t raw, TypeDialect dialect) {
    if (dialect == TypeDialect::CanonicalGGML) {
        switch(raw) {
        case 0: case 1: case 2: case 3: case 6: case 7: case 8: case 9:
        case 10: case 11: case 12: case 13: case 14: case 15:
        case 16: case 17: case 18: case 19: case 20: case 21: case 22: case 23:
        case 24: case 25: case 26: case 27: case 28: case 29: case 30:
        case 34: case 35: case 39: case 40: case 41: case 42: return raw;
        default: return std::nullopt;
        }
    }
    if (dialect == TypeDialect::LegacyGGUFHeader) {
        switch(raw) {
        case 0: return 0; case 1: return 1; case 2: return 2; case 3: return 3;
        case 10: return 12; // Q4_K
        case 11: return 13; // Q5_K
        case 12: return 11; // Q3_K
        case 9: return 10;  // Q2_K
        case 13: return 14; // Q6_K
        case 7: return 8;   // Q8_0
        case 5: return 7;   // Q5_1
        case 4: return 1;   // legacy F16_HALF
        default: return std::nullopt;
        }
    }
    switch(raw) { // EngineCommonHeader
    case 0: return 0; case 1: return 1; case 2: return 2; case 3: return 3;
    case 6: return 6; case 7: return 7; case 8: return 8;
    case 14: return 10; case 15: return 11; case 16: return 12;
    case 17: return 13; case 18: return 14;
    default: return std::nullopt;
    }
}

inline std::optional<std::uint64_t> checked_product(const std::vector<std::uint64_t>& dims) {
    if (dims.empty() || dims.size() > 4) return std::nullopt;
    std::uint64_t count = 1;
    for (auto d : dims) {
        if (!d || count > std::numeric_limits<std::uint64_t>::max() / d) return std::nullopt;
        count *= d;
    }
    return count;
}

// Pass members explicitly to avoid coupling to conflicting TensorInfo names.
// The offset convention is retained as supplied: callers must specify whether
// their source uses data-relative or file-absolute offsets before binding bytes.
inline std::optional<TensorDescriptor> adapt(std::string name,
        std::vector<std::uint64_t> dims, std::uint32_t raw_type,
        TypeDialect dialect, std::uint64_t offset, std::uint64_t bytes,
        SourceABI origin) {
    const auto t = canonical_type(raw_type, dialect);
    if (name.empty() || !t || !checked_product(dims) || bytes == 0 ||
        offset > std::numeric_limits<std::uint64_t>::max() - bytes) return std::nullopt;
    return TensorDescriptor{std::move(name), std::move(dims), *t, offset, bytes, origin};
}

// Safe helper to convert a data-relative tensor offset to an absolute file span.
inline std::optional<TensorDescriptor> make_absolute(TensorDescriptor t,
        std::uint64_t data_start, std::uint64_t file_size) {
    if (data_start > file_size || t.offset > file_size - data_start) return std::nullopt;
    const auto absolute = data_start + t.offset;
    if (t.bytes > file_size - absolute) return std::nullopt;
    t.offset = absolute;
    return t;
}
} // namespace Deep2::Authority
