// ============================================================================
// d2_session_engine.cpp — bind an existing Deep2Engine into a session
//
// d2_session_bind_deep2_engine_ptr wires a caller-owned Deep2Engine instance
// into a session (real backend, mock_backend = 0). d2_session_bind_deep2_engine
// is the legacy no-op entry point (returns 0); callers that own an engine must
// use _ptr with the instance pointer. Neither fabricates a backend.
// ============================================================================

#include "d2_session_internal.h"
#include "d2_session_engine.h"

int d2_session_bind_deep2_engine_ptr(struct Deep2StreamSession *s,
                                     void *engine_ptr) {
    if (!s || !engine_ptr) return 0;
    s->engine = engine_ptr;
    s->mock_backend = 0; // real caller-owned backend, not a mock
    return 1;
}

int d2_session_bind_deep2_engine(struct Deep2StreamSession *s) {
    // Legacy entry point: no engine instance is supplied here, so there is
    // nothing real to bind. Callers must use d2_session_bind_deep2_engine_ptr
    // with an owned Deep2Engine*. Kept as a stable no-op returning 0 so
    // existing callers keep compiling; it intentionally does not fabricate a
    // backend.
    (void)s;
    return 0;
}
