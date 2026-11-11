// Ownership probe for the vendored QuickJS-ng, second revision.
//
// The first revision concluded that JS_SetPropertyStr consumes its value.
// This probe re-tests that conclusion without freeing a value it does not
// own, and then exercises the EXACT pattern the extension host uses:
//
//     publish  : JS_SetPropertyStr(ctx, global, "vscode", fresh)
//     bind     : v = JS_GetPropertyStr(ctx, global, "vscode")
//                JS_SetPropertyStr(ctx, v, "<ns>", ns)
//                JS_SetPropertyStr(ctx, global, "vscode", v)
//
// and the variant where the shared object is published once and the binder
// only attaches, without writing the object back.

#include "quickjs.h"

#include <stdio.h>

static int failures = 0;

static void expect(int cond, const char* what) {
    fprintf(stderr, "  %-62s %s\n", what, cond ? "OK" : "FAILED");
    fflush(stderr);
    if (!cond) ++failures;
}

int main(void) {
    JSRuntime* rt = JS_NewRuntime();
    JSContext* ctx = JS_NewContext(rt);
    if (!rt || !ctx) { fprintf(stderr, "runtime init failed\n"); return 1; }

    JSValue global = JS_GetGlobalObject(ctx);

    // ---- Q1: JS_SetPropertyStr consumes the value ------------------------
    {
        JSValue obj = JS_NewObject(ctx);
        JSValue inner = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, obj, "k", inner);
        // NOT freeing inner: the setter consumed it.
        JSValue back = JS_GetPropertyStr(ctx, obj, "k");
        expect(JS_IsObject(back), "Q1 the property holds the value after the set");
        JS_FreeValue(ctx, back);
        JS_FreeValue(ctx, obj);
    }

    // ---- Q2: the host's pattern: publish, then fetch and write back -------
    {
        JSValue fresh = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, global, "vscode", fresh);   // consumes fresh
        for (int i = 0; i < 8; ++i) {
            JSValue v = JS_GetPropertyStr(ctx, global, "vscode");
            JSValue ns = JS_NewObject(ctx);
            JS_SetPropertyStr(ctx, v, "ns", ns);
            JS_SetPropertyStr(ctx, global, "vscode", v);   // consumes v
        }
        JSValue v = JS_GetPropertyStr(ctx, global, "vscode");
        JSValue ns = JS_GetPropertyStr(ctx, v, "ns");
        expect(JS_IsObject(v) && JS_IsObject(ns), "Q2 the host pattern survives eight bind cycles");
        JS_FreeValue(ctx, ns);
        JS_FreeValue(ctx, v);
    }

    // ---- Q3: the same, but the shared object is published ONCE and the
    //          binder only ATTACHES, never writing the object back ----------
    {
        JSValue fresh = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, global, "vscode2", fresh);   // consumes fresh
        for (int i = 0; i < 8; ++i) {
            JSValue v = JS_GetPropertyStr(ctx, global, "vscode2");
            JSValue ns = JS_NewObject(ctx);
            JS_SetPropertyStr(ctx, v, "ns", ns);
            JS_FreeValue(ctx, v);          // release our fetch
        }
        JSValue v = JS_GetPropertyStr(ctx, global, "vscode2");
        JSValue ns = JS_GetPropertyStr(ctx, v, "ns");
        expect(JS_IsObject(v) && JS_IsObject(ns), "Q3 attach-only leaves the shared object intact");
        JS_FreeValue(ctx, ns);
        JS_FreeValue(ctx, v);
    }

    // ---- Q4: the host pattern under stress, to surface the refcount fault -
    {
        JSValue fresh = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, global, "vscode3", fresh);
        for (int i = 0; i < 5000; ++i) {
            JSValue v = JS_GetPropertyStr(ctx, global, "vscode3");
            JSValue ns = JS_NewObject(ctx);
            JS_SetPropertyStr(ctx, v, "ns", ns);
            JS_SetPropertyStr(ctx, global, "vscode3", v);
        }
        JSValue v = JS_GetPropertyStr(ctx, global, "vscode3");
        expect(JS_IsObject(v), "Q4 the host pattern survives 5000 bind cycles");
        JS_FreeValue(ctx, v);
    }

    // ---- Q5: attach-only under stress ------------------------------------
    {
        JSValue fresh = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, global, "vscode4", fresh);
        for (int i = 0; i < 5000; ++i) {
            JSValue v = JS_GetPropertyStr(ctx, global, "vscode4");
            JSValue ns = JS_NewObject(ctx);
            JS_SetPropertyStr(ctx, v, "ns", ns);
            JS_FreeValue(ctx, v);
        }
        JSValue v = JS_GetPropertyStr(ctx, global, "vscode4");
        expect(JS_IsObject(v), "Q5 the attach-only pattern survives 5000 bind cycles");
        JS_FreeValue(ctx, v);
    }

    JS_FreeValue(ctx, global);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);

    fprintf(stderr, "\nownership probe: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
