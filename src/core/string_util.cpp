// Stub implementation for string_util.cpp
#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
namespace RawrXD { namespace Core {
size_t StringLength(const char* s) { return s ? __builtin_strlen(s) : 0; }
}} // namespace RawrXD::Core
