// _rebr_probe.cpp — name-resolution probe for Instruction inside the bridge TU.
#include "re_api.hpp"
#include "disassembler.h"

namespace RawrXD {
namespace ReverseEngineering {

static std::vector<Instruction> probe() {
    // If this compiles and static_assert passes, unqualified 'Instruction'
    // resolves to the namespace-scope struct from disassembler.h.
    static_assert(std::is_same<decltype(std::declval<Disassembler>().Disassemble(
                    nullptr, size_t(0), uint64_t(0)))::value_type,
                    Instruction>::value,
                  "Disassemble returns namespace-scope Instruction");
    return {};
}

} // namespace ReverseEngineering
} // namespace RawrXD