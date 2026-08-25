#pragma once

#include <cstddef>
#include <cstdint>

namespace RawrXD::Deep2 {

struct ProductionCertificate {
    bool gguf = false;
    bool tokenizer = false;
    bool embedding = false;

    bool q4k = false;
    bool q6k = false;

    bool forward = false;
    bool logits = false;

    bool deterministic = false;
    bool generation = false;

    bool Pass() const noexcept {
        return gguf &&
               tokenizer &&
               embedding &&
               q4k &&
               q6k &&
               forward &&
               logits &&
               deterministic &&
               generation;
    }

    std::size_t PassedCount() const noexcept {
        std::size_t n = 0;

        n += gguf;
        n += tokenizer;
        n += embedding;
        n += q4k;
        n += q6k;
        n += forward;
        n += logits;
        n += deterministic;
        n += generation;

        return n;
    }

    static constexpr std::size_t TotalCount() noexcept {
        return 9;
    }
};

extern "C" void Deep2PrintProductionCertificate(
    const ProductionCertificate& cert);

} // namespace RawrXD::Deep2
