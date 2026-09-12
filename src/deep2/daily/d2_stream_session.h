/* d2_stream_session.h — persistent daily Deep2 session (IDE/CLI contract) */
#ifndef D2_STREAM_SESSION_H
#define D2_STREAM_SESSION_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct D2GenerateRequest {
    const char *prompt;
    uint32_t max_tokens;
    float temperature;
    uint64_t seed;
    int continue_context;
} D2GenerateRequest;
typedef int (*D2TokenCallback)(void *user, uint32_t token_id,
                               const char *text, size_t text_bytes);
typedef struct Deep2StreamSession Deep2StreamSession;
Deep2StreamSession *d2_session_create(void);
void d2_session_destroy(Deep2StreamSession *s);
int d2_session_open_model(Deep2StreamSession *s, const char *gguf_path);
int d2_session_generate(Deep2StreamSession *s, const D2GenerateRequest *req,
                        D2TokenCallback cb, void *user);
void d2_session_cancel(Deep2StreamSession *s);
void d2_session_reset_context(Deep2StreamSession *s);
void d2_session_close_model(Deep2StreamSession *s);
int d2_session_model_loaded(const Deep2StreamSession *s);
uint64_t d2_session_last_generated(const Deep2StreamSession *s);
#ifdef __cplusplus
}
#endif
#endif
