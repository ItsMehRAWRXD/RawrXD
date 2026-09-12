/* d2_session_engine.h — bind real Deep2Engine behind session hooks */
#ifndef D2_SESSION_ENGINE_H
#define D2_SESSION_ENGINE_H
#ifdef __cplusplus
extern "C" {
#endif
struct Deep2StreamSession;
/* Bind an existing Deep2Engine* (caller owns lifetime). Returns 1 on success. */
int d2_session_bind_deep2_engine_ptr(struct Deep2StreamSession *s,
                                     void *engine_ptr);
/* Legacy: returns 0 — use _ptr with owned engine instance. */
int d2_session_bind_deep2_engine(struct Deep2StreamSession *s);
#ifdef __cplusplus
}
#endif
#endif
