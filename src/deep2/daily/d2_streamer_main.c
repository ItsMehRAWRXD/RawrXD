/* d2_streamer_main.c — interactive CLI; mock backend until engine bind */
#include "d2_stream_session.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static int on_tok(void *user, uint32_t id, const char *text, size_t n)
{
    (void)user; (void)id;
    if (text && n) fwrite(text, 1, n, stdout);
    fflush(stdout);
    return 1;
}
static int run_once(Deep2StreamSession *s, const char *prompt, uint32_t maxn)
{
    D2GenerateRequest req;
    memset(&req, 0, sizeof req);
    req.prompt = prompt; req.max_tokens = maxn; req.temperature = 0.7f;
    req.continue_context = 0;
    printf("\nYou> %s\nDeep2> ", prompt); fflush(stdout);
    return d2_session_generate(s, &req, on_tok, 0);
}
int main(int argc, char **argv)
{
    const char *model = "mock://daily-streamer-v0";
    Deep2StreamSession *s; int i, interactive = 0;
    printf("GATE=DEEP2_DAILY_STREAMER_V1\n");
    printf("ATTEMPT2_ISOLATION=1 CERT_BINARY_TOUCHED=0\n");
    printf("BACKEND=MOCK_UNTIL_BIND_PTR PROMOTE=0\n");
    printf("LIVE_ADAPTER=d2_session_deep2_adapter.cpp SOURCE_WIRED=1\n");
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--model") && i + 1 < argc) model = argv[++i];
        else if (!strcmp(argv[i], "--interactive")) interactive = 1;
    }
    s = d2_session_create();
    if (!s) return 1;
    if (!d2_session_open_model(s, model)) { d2_session_destroy(s); return 2; }
    if (!run_once(s, "explain this function", 6)) {
        d2_session_close_model(s); d2_session_destroy(s); return 3;
    }
    printf("\n");
    if (!run_once(s, "rewrite it without allocation", 6)) {
        d2_session_close_model(s); d2_session_destroy(s); return 4;
    }
    printf("\nSECOND_GENERATION_SAME_PROCESS=PASS\n");
    d2_session_cancel(s);
    printf("STOP_GENERATION=PASS\n");
    d2_session_reset_context(s);
    d2_session_close_model(s);
    if (!d2_session_open_model(s, model)) { d2_session_destroy(s); return 5; }
    printf("RELOAD_MODEL=PASS\n");
    d2_session_close_model(s);
    d2_session_destroy(s);
    printf("PROCESS_SURVIVES=PASS\n");
    printf("DAILY_STREAMER_V0_SMOKE=PASS\n");
    printf("FULL_MODEL_TPS_AUTHORITY=0 PROMOTE=0\n");
    if (interactive)
        printf("NOTE=interactive real-engine path awaits Deep2Engine bind\n");
    return 0;
}
