/* d2_session_deep2_adapter.cpp — bind; caller owns Deep2Engine */
#include "d2_adapter_internal.hpp"
#include "d2_session_engine.h"

extern "C" int d2_session_bind_deep2_engine(Deep2StreamSession* s) {
    (void)s;
    return 0; /* use _ptr — session does not own engine */
}

extern "C" int d2_session_bind_deep2_engine_ptr(Deep2StreamSession* s,
                                                void* engine_ptr) {
    if (!s || !engine_ptr) return 0;
    D2Deep2Binding b{};
    b.engine = engine_ptr;
    b.load_model = &d2_adapt::load_model;
    b.generate = &d2_adapt::generate;
    b.request_cancel = &d2_adapt::request_cancel;
    b.reset_context = &d2_adapt::reset_context;
    b.unload_model = &d2_adapt::unload_model;
    return d2_session_install_binding(s, &b);
}
