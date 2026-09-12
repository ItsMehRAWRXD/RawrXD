#include "d2_endurance_gate.h"
#include <string.h>

int d2_endurance_run(
    D2DailyStreamer* s,
    const D2EndurancePlan* p,
    size_t n,
    D2EnduranceReport* r)
{
    size_t i;
    if (!s || !p || !n || !r) return D2X_EINVAL;
    memset(r, 0, sizeof(*r));

    for (i = 0; i < n; ++i) {
        uint32_t g;
        int ok = 1;

        if (d2_daily_open_model(s, p[i].model_path) != D2X_OK) {
            r->failures++;
            r->cases_run++;
            continue;
        }

        for (g = 0; g < p[i].generations; ++g) {
            uint64_t before = s->generated_tokens;
            int rc = d2_daily_generate(
                s, p[i].prompt, p[i].prompt_bytes,
                p[i].tokens_per_generation);

            r->generations++;
            r->tokens += s->generated_tokens - before;
            if (rc != D2X_OK) {
                ok = 0;
                r->failures++;
                break;
            }

            if (g + 1 < p[i].generations && p[i].reset_between) {
                if (d2_daily_reset_context(s) != D2X_OK) {
                    ok = 0;
                    r->failures++;
                    break;
                }
            }
        }

        if (d2_daily_close_model(s) != D2X_OK) {
            ok = 0;
            r->failures++;
        }

        r->cases_run++;
        if (ok) r->cases_pass++;
        (void)p[i].reopen_after_case;
    }

    return d2_endurance_pass(r) ? D2X_OK : D2X_EAUTH;
}

int d2_endurance_pass(const D2EnduranceReport* r) {
    if (!r || !r->cases_run) return 0;
    return r->cases_pass == r->cases_run && r->failures == 0;
}
