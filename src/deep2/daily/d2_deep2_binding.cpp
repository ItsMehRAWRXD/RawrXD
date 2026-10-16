// ============================================================================
// d2_deep2_binding.cpp — real binding between a session and Deep2Engine
//
// Replaces the mock/stub binding: d2_session_install_binding installs live
// Deep2Engine function pointers and d2_session_backend_is_mock() reports 0
// (no mock backend). No simulated results.
// ============================================================================

#include "d2_session_internal.h"
#include "d2_deep2_binding.h"

int d2_session_install_binding(Deep2StreamSession *s, const D2Deep2Binding *b) {
    if (!s || !b) return 0;
    s->engine = b->engine;
    s->fn_open = b->load_model;
    s->fn_gen = b->generate;
    s->fn_cancel = b->request_cancel;
    s->fn_reset = b->reset_context;
    s->fn_close = b->unload_model;
    // Live binding installed: not a mock.
    s->mock_backend = 0;
    return 1;
}

int d2_session_backend_is_mock(const Deep2StreamSession *s) {
    // With the mock backend removed, this always reports 0 (real backend).
    return s ? (s->mock_backend != 0 ? 1 : 0) : 0;
}
