#pragma once
// DEPRECATED shim — use Deep2::QuantTypeTable.hpp (canonical ggml IDs + geometry).
// This header previously mixed overlapping numeric IDs (ABI hazard).
#include "QuantTypeTable.hpp"

// Legacy flat enum alias for call sites that used non-scoped GGMLType.
using ::Deep2::GGMLType;
using ::Deep2::QuantTypeDescriptor;
using ::Deep2::LookupQuantType;
using ::Deep2::QuantTypeName;
