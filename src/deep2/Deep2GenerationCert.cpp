#include "Deep2GenerationCert.h"

namespace RawrXD::Deep2 {

GenerationCertificate CertifyGeneration(
    const std::vector<std::uint32_t>& first_tokens,
    const std::vector<std::uint32_t>& second_tokens,
    const DeterminismTrace& first_trace,
    const DeterminismTrace& second_trace,
    std::size_t expected_tokens)
{
    GenerationCertificate r;

    r.valid = true;

    r.first_tokens = first_tokens;
    r.second_tokens = second_tokens;

    r.token_count_valid =
        first_tokens.size() == expected_tokens &&
        second_tokens.size() == expected_tokens;

    r.deterministic =
        first_tokens == second_tokens &&
        first_trace.Equal(second_trace);

    r.finite = true;

    r.first_trace = first_trace;
    r.second_trace = second_trace;

    return r;
}

} // namespace RawrXD::Deep2
