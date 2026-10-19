#include "nilw_auth.hpp"
#include <stdio.h>

static const char* State(uint64_t x) {
    return x ? "PASS" : "NOT_PASS";
}

int main() {
    rawrxd::NilwWitness w{};
    rawrxd::NilwResult r = rawrxd::EvaluateNilw(w);

    printf("RAWRXD_NILW_AUTH_NODEP\n");
    printf("VALID=%s\n", State(r.valid));
    printf("NUMERATOR_SEPARATION_OK=%s\n", State(r.numerator_separation_ok));
    printf("TOKEN_NILW_X1E9=%llu\n", (unsigned long long)r.token_nilw_x1e9);
    printf("ACTIVE_CODEC_BPW_X1E6=%llu\n", (unsigned long long)r.active_codec_bpw_x1e6);
    printf("ACTIVE_NEW_BPW_X1E6=%llu\n", (unsigned long long)r.active_new_bpw_x1e6);
    printf("PHYSICALIZATION_PPM=%llu\n", (unsigned long long)r.physicalization_ppm);
    printf("NEW_INFORMATION_FRACTION_PPM=%llu\n",
           (unsigned long long)r.new_information_fraction_ppm);
    printf("NEW_PAYLOAD_BYTES_PER_TOKEN=%llu\n",
           (unsigned long long)r.new_payload_bytes_per_token);
    printf("TPS_X1000=%llu\n", (unsigned long long)r.tps_x1000);
    printf("INFORMATION_RATE_BPS=%llu\n",
           (unsigned long long)r.information_rate_bps);
    printf("ENVELOPE_100MB_TOKEN=%s\n", State(r.envelope_100mb_token));
    printf("ENVELOPE_10TPS=%s\n", State(r.envelope_10tps));
    printf("ENVELOPE_1GBPS=%s\n", State(r.envelope_1gbps));
    printf("INDEPENDENT_PROOFS_PASS=%s\n", State(r.independent_proofs_pass));
    printf("NO_FULL_MATERIALIZATION=%s\n", State(r.no_full_materialization));
    printf("AUTHORIZED_PASS=%s\n", State(r.authorized_pass));
    return 0;
}
