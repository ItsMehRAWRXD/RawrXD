/*
 * QuickJS - Minimal stub implementation for RawrXD
 */

#include "quickjs.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Stub implementations */

JSRuntime *JS_NewRuntime(void) {
    return (JSRuntime *)calloc(1, sizeof(void*));
}

void JS_FreeRuntime(JSRuntime *rt) {
    free(rt);
}

JSContext *JS_NewContext(JSRuntime *rt) {
    (void)rt;
    return (JSContext *)calloc(1, sizeof(void*));
}

void JS_FreeContext(JSContext *ctx) {
    free(ctx);
}

JSValue JS_NewString(JSContext *ctx, const char *str) {
    (void)ctx;
    (void)str;
    return (JSValue){0};
}

JSValue JS_NewStringLen(JSContext *ctx, const char *str, size_t len) {
    (void)ctx;
    (void)str;
    (void)len;
    return (JSValue){0};
}

JSValue JS_NewInt32(JSContext *ctx, int32_t val) {
    (void)ctx;
    (void)val;
    return (JSValue){0};
}

JSValue JS_NewInt64(JSContext *ctx, int64_t val) {
    (void)ctx;
    (void)val;
    return (JSValue){0};
}

JSValue JS_NewFloat64(JSContext *ctx, double val) {
    (void)ctx;
    (void)val;
    return (JSValue){0};
}

JSValue JS_NewBool(JSContext *ctx, int val) {
    (void)ctx;
    (void)val;
    return (JSValue){0};
}

JSValue JS_NewNull(void) {
    return (JSValue){0};
}

JSValue JS_NewUndefined(void) {
    return (JSValue){0};
}

JSValue JS_NewObject(JSContext *ctx) {
    (void)ctx;
    return (JSValue){0};
}

JSValue JS_NewArray(JSContext *ctx) {
    (void)ctx;
    return (JSValue){0};
}

JSValue JS_NewError(JSContext *ctx) {
    (void)ctx;
    return (JSValue){0};
}

void JS_FreeValue(JSContext *ctx, JSValue v) {
    (void)ctx;
    (void)v;
}

void JS_FreeValueRT(JSRuntime *rt, JSValue v) {
    (void)rt;
    (void)v;
}

const char *JS_ToCString(JSContext *ctx, JSValue val) {
    (void)ctx;
    (void)val;
    return "";
}

const char *JS_ToCStringLen(JSContext *ctx, size_t *plen, JSValue val) {
    (void)ctx;
    (void)val;
    if (plen) *plen = 0;
    return "";
}

void JS_FreeCString(JSContext *ctx, const char *ptr) {
    (void)ctx;
    (void)ptr;
}

int JS_ToInt32(JSContext *ctx, int32_t *pres, JSValue val) {
    (void)ctx;
    (void)val;
    if (pres) *pres = 0;
    return 0;
}

int JS_ToInt64(JSContext *ctx, int64_t *pres, JSValue val) {
    (void)ctx;
    (void)val;
    if (pres) *pres = 0;
    return 0;
}

int JS_ToFloat64(JSContext *ctx, double *pres, JSValue val) {
    (void)ctx;
    (void)val;
    if (pres) *pres = 0.0;
    return 0;
}

int JS_ToBool(JSContext *ctx, JSValue val) {
    (void)ctx;
    (void)val;
    return 0;
}

int JS_IsUndefined(JSValue val) {
    (void)val;
    return 1;
}

int JS_IsNull(JSValue val) {
    (void)val;
    return 0;
}

int JS_IsBool(JSValue val) {
    (void)val;
    return 0;
}

int JS_IsNumber(JSValue val) {
    (void)val;
    return 0;
}

int JS_IsString(JSValue val) {
    (void)val;
    return 0;
}

int JS_IsObject(JSValue val) {
    (void)val;
    return 0;
}

int JS_IsArray(JSContext *ctx, JSValue val) {
    (void)ctx;
    (void)val;
    return 0;
}

int JS_IsError(JSContext *ctx, JSValue val) {
    (void)ctx;
    (void)val;
    return 0;
}

int JS_IsException(JSValue val) {
    (void)val;
    return 0;
}

JSValue JS_GetProperty(JSContext *ctx, JSValue obj, JSAtom prop) {
    (void)ctx;
    (void)obj;
    (void)prop;
    return (JSValue){0};
}

JSValue JS_GetPropertyStr(JSContext *ctx, JSValue obj, const char *prop) {
    (void)ctx;
    (void)obj;
    (void)prop;
    return (JSValue){0};
}

JSValue JS_GetPropertyUint32(JSContext *ctx, JSValue obj, uint32_t idx) {
    (void)ctx;
    (void)obj;
    (void)idx;
    return (JSValue){0};
}

int JS_SetProperty(JSContext *ctx, JSValue obj, JSAtom prop, JSValue val) {
    (void)ctx;
    (void)obj;
    (void)prop;
    (void)val;
    return -1;
}

int JS_SetPropertyStr(JSContext *ctx, JSValue obj, const char *prop, JSValue val) {
    (void)ctx;
    (void)obj;
    (void)prop;
    (void)val;
    return -1;
}

int JS_SetPropertyUint32(JSContext *ctx, JSValue obj, uint32_t idx, JSValue val) {
    (void)ctx;
    (void)obj;
    (void)idx;
    (void)val;
    return -1;
}

JSValue JS_GetGlobalObject(JSContext *ctx) {
    (void)ctx;
    return (JSValue){0};
}

JSValue JS_Call(JSContext *ctx, JSValue func, JSValue this_obj, int argc, JSValue *argv) {
    (void)ctx;
    (void)func;
    (void)this_obj;
    (void)argc;
    (void)argv;
    return (JSValue){0};
}

JSValue JS_CallConstructor(JSContext *ctx, JSValue func, int argc, JSValue *argv) {
    (void)ctx;
    (void)func;
    (void)argc;
    (void)argv;
    return (JSValue){0};
}

JSValue JS_Eval(JSContext *ctx, const char *input, size_t input_len, const char *filename, int eval_flags) {
    (void)ctx;
    (void)input;
    (void)input_len;
    (void)filename;
    (void)eval_flags;
    return (JSValue){0};
}

JSAtom JS_NewAtom(JSContext *ctx, const char *str) {
    (void)ctx;
    (void)str;
    return 0;
}

JSAtom JS_NewAtomLen(JSContext *ctx, const char *str, size_t len) {
    (void)ctx;
    (void)str;
    (void)len;
    return 0;
}

void JS_FreeAtom(JSContext *ctx, JSAtom v) {
    (void)ctx;
    (void)v;
}

void JS_FreeAtomRT(JSRuntime *rt, JSAtom v) {
    (void)rt;
    (void)v;
}

JSValue JS_GetException(JSContext *ctx) {
    (void)ctx;
    return (JSValue){0};
}

void JS_ResetUncatchableError(JSContext *ctx) {
    (void)ctx;
}

void JS_SetModuleLoaderFunc(JSRuntime *rt, JSModuleNormalizeFunc *module_normalize, JSModuleLoaderFunc *module_loader, void *opaque) {
    (void)rt;
    (void)module_normalize;
    (void)module_loader;
    (void)opaque;
}

void js_std_init_handlers(JSRuntime *rt) {
    (void)rt;
}

void js_std_free_handlers(JSRuntime *rt) {
    (void)rt;
}

void js_std_add_helpers(JSContext *ctx, int argc, const char **argv) {
    (void)ctx;
    (void)argc;
    (void)argv;
}

void js_std_loop(JSContext *ctx) {
    (void)ctx;
}

int js_std_init_module(JSContext *ctx, const char *module_name) {
    (void)ctx;
    (void)module_name;
    return -1;
}

void JS_SetHostPromiseRejectionTracker(JSRuntime *rt, void *cb, void *opaque) {
    (void)rt;
    (void)cb;
    (void)opaque;
}

void JS_ComputeMemoryUsage(JSRuntime *rt, JSMemoryUsage *s) {
    (void)rt;
    if (s) {
        memset(s, 0, sizeof(*s));
    }
}

int64_t JS_GetMemoryUsage(JSRuntime *rt) {
    (void)rt;
    return 0;
}

JSValue JS_NewCFunction(JSContext *ctx, JSCFunction *func, const char *name, int length) {
    (void)ctx;
    (void)func;
    (void)name;
    (void)length;
    return (JSValue){0};
}

JSValue JS_NewCFunctionMagic(JSContext *ctx, JSCFunctionMagic *func, const char *name, int length, int cproto, int magic) {
    (void)ctx;
    (void)func;
    (void)name;
    (void)length;
    (void)cproto;
    (void)magic;
    return (JSValue){0};
}

JSValue JS_ParseJSON(JSContext *ctx, const char *buf, size_t buf_len, const char *filename) {
    (void)ctx;
    (void)buf;
    (void)buf_len;
    (void)filename;
    return (JSValue){0};
}

JSValue JS_JSONStringify(JSContext *ctx, JSValue obj, JSValue replacer, JSValue space) {
    (void)ctx;
    (void)obj;
    (void)replacer;
    (void)space;
    return (JSValue){0};
}

int JS_NewClass(JSRuntime *rt, JSClassID class_id, const JSClassDef *class_def) {
    (void)rt;
    (void)class_id;
    (void)class_def;
    return 0;
}

JSClassID JS_NewClassID(JSClassID *pclass_id) {
    static JSClassID next_id = 1;
    if (pclass_id) {
        *pclass_id = next_id++;
        return *pclass_id;
    }
    return next_id++;
}

JSValue JS_NewObjectClass(JSContext *ctx, JSClassID class_id) {
    (void)ctx;
    (void)class_id;
    return (JSValue){0};
}

void *JS_GetOpaque(JSValue obj, JSClassID class_id) {
    (void)obj;
    (void)class_id;
    return NULL;
}

void *JS_GetOpaque2(JSContext *ctx, JSValue obj, JSClassID class_id) {
    (void)ctx;
    (void)obj;
    (void)class_id;
    return NULL;
}

void JS_SetOpaque(JSValue obj, void *opaque) {
    (void)obj;
    (void)opaque;
}
