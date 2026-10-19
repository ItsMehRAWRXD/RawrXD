#include "deep2_audit_nodep.h"
#include <string.h>

extern "C" int d2_daily_bind(D2DailySession* s, const D2EngineOps* ops, const char* model_path) {
    if (!s || !ops || !model_path || !*model_path) return 0;
    if (!ops->ctx || !ops->open_model || !ops->generate || !ops->reset_context || !ops->close_model) return 0;
    memset(s, 0, sizeof(*s));
    s->ops = *ops;
    if (!s->ops.open_model(s->ops.ctx, model_path, &s->model_cookie) || !s->model_cookie) return 0;
    s->open = 1;
    return 1;
}

extern "C" int d2_daily_generate(D2DailySession* s, const char* prompt, uint32_t max_tokens,
                                  int (*on_token)(void*, const char*, uint32_t), void* user,
                                  uint64_t* out_generated_tokens) {
    if (!s || !s->open || !prompt || !on_token || !out_generated_tokens || !max_tokens) return 0;
    s->cancel_flag = 0;
    *out_generated_tokens = 0;
    const int ok = s->ops.generate(s->ops.ctx, s->model_cookie, prompt, max_tokens,
                                   &s->cancel_flag, on_token, user, out_generated_tokens);
    if (ok) s->generations_completed++;
    else if (s->cancel_flag) s->survived_cancel = 1;
    return ok ? 1 : 0;
}

extern "C" int d2_daily_cancel(D2DailySession* s) {
    if (!s || !s->open) return 0;
    s->cancel_flag = 1;
    return 1;
}
extern "C" int d2_daily_reset(D2DailySession* s) {
    if (!s || !s->open) return 0;
    s->cancel_flag = 0;
    return s->ops.reset_context(s->ops.ctx, s->model_cookie) ? 1 : 0;
}
extern "C" int d2_daily_close(D2DailySession* s) {
    if (!s || !s->open) return 0;
    const int ok = s->ops.close_model(s->ops.ctx, s->model_cookie);
    s->open = 0; s->model_cookie = 0; s->cancel_flag = 0;
    return ok ? 1 : 0;
}
extern "C" int d2_daily_ready(const D2DailySession* s) {
    return (s && s->open && s->generations_completed >= 2) ? 1 : 0;
}
