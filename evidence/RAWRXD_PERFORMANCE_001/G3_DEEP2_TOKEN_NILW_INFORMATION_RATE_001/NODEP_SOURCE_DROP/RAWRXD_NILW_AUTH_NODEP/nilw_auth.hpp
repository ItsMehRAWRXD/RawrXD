#pragma once
#include <stdint.h>

namespace rawrxd {

enum ProofState : uint32_t {
    PROOF_NOT_RUN = 0,
    PROOF_FAIL    = 1,
    PROOF_PASS    = 2
};

enum NilwForm : uint32_t {
    NILW_FORM_A = 1,
    NILW_FORM_B = 2
};

struct NilwWitness {
    NilwForm form = NILW_FORM_A;

    uint64_t total_logical_weights = 0;
    uint64_t active_logical_weights = 0;

    // FORM A numerator basis:
    uint64_t active_representation_bits = 0;
    uint64_t new_information_bits = 0;

    // FORM B numerator basis:
    uint64_t new_payload_bits = 0;

    uint64_t overhead_bits = 0;

    uint64_t generated_tokens = 0;
    uint64_t wall_ns = 0;

    uint64_t full_materialization = 0;

    ProofState active_subset_measured = PROOF_NOT_RUN;
    ProofState reuse_measured = PROOF_NOT_RUN;
    ProofState overhead_accounted = PROOF_NOT_RUN;
    ProofState quality_gate = PROOF_NOT_RUN;
};

struct NilwResult {
    uint64_t valid = 0;
    uint64_t numerator_separation_ok = 0;

    uint64_t token_nilw_x1e9 = 0;
    uint64_t active_codec_bpw_x1e6 = 0;
    uint64_t active_new_bpw_x1e6 = 0;
    uint64_t physicalization_ppm = 0;
    uint64_t new_information_fraction_ppm = 0;

    uint64_t new_payload_bytes_per_token = 0;
    uint64_t tps_x1000 = 0;
    uint64_t information_rate_bps = 0;

    uint64_t envelope_100mb_token = 0;
    uint64_t envelope_10tps = 0;
    uint64_t envelope_1gbps = 0;

    uint64_t independent_proofs_pass = 0;
    uint64_t no_full_materialization = 0;

    uint64_t authorized_pass = 0;
};

uint64_t RatioScaled(uint64_t num, uint64_t den, uint64_t scale);
NilwResult EvaluateNilw(const NilwWitness& w);

}
