#pragma once

#include "Deep2Determinism.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace RawrXD::Deep2 {

struct GenerationCertificate {
    bool valid = false;
    bool finite = false;
    bool deterministic = false;
    bool token_count_valid = false;

    std::vector<std::uint32_t> first_tokens;
    std::vector<std::uint32_t> second_tokens;

    DeterminismTrace first_trace;
    DeterminismTrace second_trace;

    bool Pass() const noexcept {
        return valid &&
               finite &&
               deterministic &&
               token_count_valid;
    }
};

GenerationCertificate CertifyGeneration(
    const std::vector<std::uint32_t>& first_tokens,
    const std::vector<std::uint32_t>& second_tokens,
    const DeterminismTrace& first_trace,
    const DeterminismTrace& second_trace,
    std::size_t expected_tokens);

} // namespace RawrXD::Deep2
