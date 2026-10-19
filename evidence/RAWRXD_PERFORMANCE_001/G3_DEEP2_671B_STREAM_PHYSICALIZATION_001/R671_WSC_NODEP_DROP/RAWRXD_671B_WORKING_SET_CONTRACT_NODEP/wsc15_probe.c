#include "wsc15.h"
#include <stdio.h>
#include <string.h>

#define MiB(x) ((uint64_t)(x) * 1024ull * 1024ull)
#define GiB(x) ((uint64_t)(x) * 1024ull * 1024ull * 1024ull)

static int run_positive(void) {
    wsc15_raw r;
    wsc15_result o;
    unsigned i;
    memset(&r, 0, sizeof(r));

    r.file_bytes = GiB(384);
    r.window_bytes = MiB(64);
    r.slot_count = 4;

    r.request_observed = 1;
    r.request_offset = GiB(320) + 4096;
    r.request_bytes = MiB(16);

    r.current_mapped_bytes = MiB(192);
    r.peak_mapped_bytes = MiB(256);
    r.configured_max_mapped_bytes = MiB(256);

    r.cache_hits = 9;
    r.cache_misses = 17;
    r.reused_bytes = MiB(72);
    r.newly_mapped_bytes = MiB(768);
    r.evictions = 13;

    r.live_pins_before_evict = 0;
    r.evictions_while_pinned = 0;
    r.non_lru_evictions = 0;

    r.full_tensor_fallback_count = 0;

    r.leases_acquired = 26;
    r.leases_released = 26;
    r.invalid_release_count = 0;

    r.token_observed = 1;
    r.token_id = 1;
    r.token_begin_mapped_bytes = MiB(128);
    r.token_end_mapped_bytes = MiB(192);
    r.token_peak_mapped_bytes = MiB(256);
    r.token_newly_mapped_bytes = MiB(96);
    r.token_reused_bytes = MiB(32);

    wsc15_evaluate(&r, &o);

    for (i = 0; i < WSC15_COUNT; ++i)
        printf("WSC%02u=%llu\n", i + 1, (unsigned long long)o.witness[i]);
    printf("PASS_COUNT=%llu\n", (unsigned long long)o.pass_count);
    printf("FAIL_COUNT=%llu\n", (unsigned long long)o.fail_count);
    printf("NOTRUN_COUNT=%llu\n", (unsigned long long)o.not_run_count);
    printf("CONTRACT_PASS=%llu\n", (unsigned long long)o.contract_pass);

    return o.contract_pass == 1 && o.pass_count == 15 && o.fail_count == 0 && o.not_run_count == 0;
}

static int run_negative(void) {
    wsc15_raw r;
    wsc15_result o;
    memset(&r, 0, sizeof(r));

    /* Deliberately omit observations: NOT_RUN must never authorize. */
    wsc15_evaluate(&r, &o);
    printf("ZERO_CONTRACT_PASS=%llu\n", (unsigned long long)o.contract_pass);
    printf("ZERO_NOTRUN_COUNT=%llu\n", (unsigned long long)o.not_run_count);

    return o.contract_pass == 0 && o.not_run_count > 0;
}

int main(void) {
    if (!run_negative()) {
        puts("WSC15_ZERO=FAIL");
        return 2;
    }
    if (!run_positive()) {
        puts("WSC15_POSITIVE=FAIL");
        return 3;
    }
    puts("WSC15_PROBE=PASS");
    return 0;
}
