#include "wsc15.h"
#include <string.h>
#include <limits.h>

static int add_overflow_u64(uint64_t a, uint64_t b, uint64_t* out) {
    if (a > UINT64_MAX - b) return 1;
    *out = a + b;
    return 0;
}

static void set_notrun(wsc15_result* out) {
    unsigned i;
    for (i = 0; i < WSC15_COUNT; ++i) out->witness[i] = WSC_NOT_RUN;
}

void wsc15_evaluate(const wsc15_raw* r, wsc15_result* o) {
    uint64_t req_end = 0;
    uint64_t theoretical_max = 0;
    unsigned i;

    if (!o) return;
    memset(o, 0, sizeof(*o));
    set_notrun(o);
    if (!r) goto summarize;

    /* W01: fixed slot bound is present and nonzero. */
    if (r->slot_count)
        o->witness[WSC01_FIXED_SLOT_BOUND] = WSC_PASS;

    /* W02: fixed window bound is present and nonzero. */
    if (r->window_bytes)
        o->witness[WSC02_FIXED_WINDOW_BOUND] = WSC_PASS;

    /* W03/W04 require an observed request. */
    if (r->request_observed) {
        if (!r->request_bytes || add_overflow_u64(r->request_offset, r->request_bytes, &req_end))
            o->witness[WSC03_REQUEST_IN_FILE_BOUNDS] = WSC_FAIL;
        else
            o->witness[WSC03_REQUEST_IN_FILE_BOUNDS] =
                (req_end <= r->file_bytes) ? WSC_PASS : WSC_FAIL;

        o->witness[WSC04_SINGLE_WINDOW_REQUEST] =
            (r->window_bytes && r->request_bytes <= r->window_bytes) ? WSC_PASS : WSC_FAIL;
    }

    /* W05: no eviction can occur while the selected victim is pinned. */
    if (r->evictions || r->live_pins_before_evict || r->evictions_while_pinned)
        o->witness[WSC05_PIN_SAFE_EVICTION] =
            (r->evictions_while_pinned == 0) ? WSC_PASS : WSC_FAIL;

    /* W06: eviction policy must not report a non-LRU victim. */
    if (r->evictions || r->non_lru_evictions)
        o->witness[WSC06_UNPINNED_LRU_ONLY] =
            (r->non_lru_evictions == 0) ? WSC_PASS : WSC_FAIL;

    /* W07: hard law — no whole-tensor fallback. */
    o->witness[WSC07_NO_FULL_TENSOR_FALLBACK] =
        (r->full_tensor_fallback_count == 0) ? WSC_PASS : WSC_FAIL;

    /* Derive theoretical slot*window bound with overflow rejection. */
    if (!r->slot_count || !r->window_bytes ||
        r->slot_count > UINT64_MAX / r->window_bytes) {
        theoretical_max = 0;
    } else {
        theoretical_max = r->slot_count * r->window_bytes;
    }

    /* W08: current mapped bytes stay inside both theoretical and configured bounds. */
    if (theoretical_max && r->configured_max_mapped_bytes) {
        o->witness[WSC08_CURRENT_BYTES_BOUNDED] =
            (r->current_mapped_bytes <= theoretical_max &&
             r->current_mapped_bytes <= r->configured_max_mapped_bytes)
                ? WSC_PASS : WSC_FAIL;
    }

    /* W09: peak mapped bytes stay inside both bounds. */
    if (theoretical_max && r->configured_max_mapped_bytes) {
        o->witness[WSC09_PEAK_BYTES_BOUNDED] =
            (r->peak_mapped_bytes <= theoretical_max &&
             r->peak_mapped_bytes <= r->configured_max_mapped_bytes)
                ? WSC_PASS : WSC_FAIL;
    }

    /* W10: a reported hit must correspond to nonzero reuse bytes. */
    if (r->cache_hits || r->reused_bytes) {
        o->witness[WSC10_CACHE_REUSE_ACCOUNTED] =
            (r->cache_hits > 0 && r->reused_bytes > 0) ? WSC_PASS : WSC_FAIL;
    }

    /* W11: a miss implies new mapping bytes were observed. */
    if (r->cache_misses || r->newly_mapped_bytes) {
        o->witness[WSC11_NEW_BYTES_ACCOUNTED] =
            (r->cache_misses > 0 && r->newly_mapped_bytes > 0) ? WSC_PASS : WSC_FAIL;
    }

    /* W12: eviction accounting must be possible only after at least one miss. */
    if (r->evictions) {
        o->witness[WSC12_EVICTION_ACCOUNTED] =
            (r->cache_misses > 0 && r->evictions <= r->cache_misses) ? WSC_PASS : WSC_FAIL;
    }

    /* W13: every lease acquired in the measured scope must be released exactly once. */
    if (r->leases_acquired || r->leases_released || r->invalid_release_count) {
        o->witness[WSC13_LEASE_LIFETIME_CLOSED] =
            (r->leases_acquired == r->leases_released &&
             r->invalid_release_count == 0) ? WSC_PASS : WSC_FAIL;
    }

    /* W14: token scope exists and residency closes inside configured bounds. */
    if (r->token_observed) {
        o->witness[WSC14_TOKEN_WORKING_SET_CLOSED] =
            (r->configured_max_mapped_bytes &&
             r->token_peak_mapped_bytes <= r->configured_max_mapped_bytes &&
             r->token_end_mapped_bytes <= r->configured_max_mapped_bytes &&
             (r->token_newly_mapped_bytes > 0 || r->token_reused_bytes > 0))
                ? WSC_PASS : WSC_FAIL;
    }

    /* W15 is conjunction only. */
    {
        uint64_t p = 0, f = 0, n = 0;
        for (i = 0; i < 14; ++i) {
            if (o->witness[i] == WSC_PASS) ++p;
            else if (o->witness[i] == WSC_FAIL) ++f;
            else ++n;
        }
        if (p == 14 && f == 0 && n == 0) {
            o->witness[WSC15_CONJUNCTION] = WSC_PASS;
            o->contract_pass = 1;
        } else {
            o->witness[WSC15_CONJUNCTION] = WSC_FAIL;
            o->contract_pass = 0;
        }
    }

summarize:
    o->pass_count = o->fail_count = o->not_run_count = 0;
    for (i = 0; i < WSC15_COUNT; ++i) {
        if (o->witness[i] == WSC_PASS) ++o->pass_count;
        else if (o->witness[i] == WSC_FAIL) ++o->fail_count;
        else ++o->not_run_count;
    }
}
