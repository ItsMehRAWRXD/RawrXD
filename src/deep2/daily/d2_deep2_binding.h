/* d2_deep2_binding.h — narrow ABI between session and Deep2Engine */
#ifndef D2_DEEP2_BINDING_H
#define D2_DEEP2_BINDING_H
#include "d2_stream_session.h"
#include "d2_cancel.h"
#include "d2_stream_metrics.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct D2Deep2Binding {
    void *engine;
    int (*load_model)(void *engine, const char *gguf_path);
    int (*generate)(void *engine, const D2GenerateRequest *req,
                    D2TokenCallback cb, void *user, D2Cancel *cancel,
                    D2StreamMetrics *metrics);
    void (*request_cancel)(void *engine);
    void (*reset_context)(void *engine);
    void (*unload_model)(void *engine);
} D2Deep2Binding;
/* Install live Deep2 hooks; MOCK_BACKEND becomes 0. */
int d2_session_install_binding(Deep2StreamSession *s, const D2Deep2Binding *b);
int d2_session_backend_is_mock(const Deep2StreamSession *s);
#ifdef __cplusplus
}
#endif
#endif
