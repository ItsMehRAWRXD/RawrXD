#include "deep2_endurance.h"

int d2_run_endurance(
    D2Streamer* s,
    const D2EnduranceCase* cases,
    size_t case_count,
    D2EnduranceResult* out)
{
    size_t i;
    if (!s || !cases || !case_count || !out) return D2_EINVAL;
    *out = (D2EnduranceResult){0};

    for (i = 0; i < case_count; ++i) {
        uint32_t g;
        int rc;
        uint32_t case_ok = 1;

        rc = d2_streamer_open(s, cases[i].model_path);
        if (rc) {
            out->callback_failures++;
            out->cases_run++;
            continue;
        }

        for (g = 0; g < cases[i].generations; ++g) {
            uint64_t before = s->total_generated_tokens;
            rc = d2_streamer_generate(
                s,
                cases[i].prompt,
                cases[i].prompt_bytes,
                cases[i].tokens_per_generation);

            out->generations_run++;
            out->tokens_generated += s->total_generated_tokens - before;

            if (rc == D2_EAUTH) {
                out->authority_failures++;
                case_ok = 0;
                break;
            }
            if (rc != D2_OK) {
                out->callback_failures++;
                case_ok = 0;
                break;
            }
            if (s->device_lost_seen) {
                out->device_lost_failures++;
                case_ok = 0;
                break;
            }

            if (g + 1 < cases[i].generations &&
                cases[i].resets_between_generations)
            {
                if (d2_streamer_reset(s) != D2_OK) {
                    out->callback_failures++;
                    case_ok = 0;
                    break;
                }
            }
        }

        if (d2_streamer_close(s) != D2_OK) {
            out->callback_failures++;
            case_ok = 0;
        }

        out->external_runtime_calls += s->external_runtime_calls;
        out->cases_run++;
        if (case_ok) out->cases_passed++;
    }

    return d2_endurance_pass(out) ? D2_OK : D2_EAUTH;
}

int d2_endurance_pass(const D2EnduranceResult* r) {
    if (!r || !r->cases_run) return 0;
    return
        r->cases_passed == r->cases_run &&
        r->callback_failures == 0 &&
        r->authority_failures == 0 &&
        r->device_lost_failures == 0 &&
        r->external_runtime_calls == 0;
}
