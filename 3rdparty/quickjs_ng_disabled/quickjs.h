#ifndef QUICKJS_H
#define QUICKJS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Minimal QuickJS API stubs for compilation */

typedef struct JSRuntime JSRuntime;
typedef struct JSContext JSContext;
typedef struct JSValue JSValue;
typedef uint32_t JSAtom;

#define JS_NULL JSValue{0}
#define JS_UNDEFINED JSValue{0}
#define JS_EXCEPTION JSValue{0}
#define JS_UNINITIALIZED JSValue{0}

#define JS_EVAL_TYPE_GLOBAL 0
#define JS_EVAL_TYPE_MODULE 1
#define JS_EVAL_FLAG_STRICT (1 << 3)
#define JS_EVAL_FLAG_COMPILE_ONLY (1 << 7)

/* Runtime and context management */
JSRuntime *JS_NewRuntime(void);
void JS_FreeRuntime(JSRuntime *rt);
JSContext *JS_NewContext(JSRuntime *rt);
void JS_FreeContext(JSContext *ctx);

/* Value operations */
JSValue JS_NewString(JSContext *ctx, const char *str);
JSValue JS_NewStringLen(JSContext *ctx, const char *str, size_t len);
JSValue JS_NewInt32(JSContext *ctx, int32_t val);
JSValue JS_NewInt64(JSContext *ctx, int64_t val);
JSValue JS_NewFloat64(JSContext *ctx, double val);
JSValue JS_NewBool(JSContext *ctx, int val);
JSValue JS_NewNull(void);
JSValue JS_NewUndefined(void);
JSValue JS_NewObject(JSContext *ctx);
JSValue JS_NewArray(JSContext *ctx);
JSValue JS_NewError(JSContext *ctx);

void JS_FreeValue(JSContext *ctx, JSValue v);
void JS_FreeValueRT(JSRuntime *rt, JSValue v);

const char *JS_ToCString(JSContext *ctx, JSValue val);
const char *JS_ToCStringLen(JSContext *ctx, size_t *plen, JSValue val);
void JS_FreeCString(JSContext *ctx, const char *ptr);

int JS_ToInt32(JSContext *ctx, int32_t *pres, JSValue val);
int JS_ToInt64(JSContext *ctx, int64_t *pres, JSValue val);
int JS_ToFloat64(JSContext *ctx, double *pres, JSValue val);
int JS_ToBool(JSContext *ctx, JSValue val);

int JS_IsUndefined(JSValue val);
int JS_IsNull(JSValue val);
int JS_IsBool(JSValue val);
int JS_IsNumber(JSValue val);
int JS_IsString(JSValue val);
int JS_IsObject(JSValue val);
int JS_IsArray(JSContext *ctx, JSValue val);
int JS_IsError(JSContext *ctx, JSValue val);
int JS_IsException(JSValue val);

/* Object operations */
JSValue JS_GetProperty(JSContext *ctx, JSValue obj, JSAtom prop);
JSValue JS_GetPropertyStr(JSContext *ctx, JSValue obj, const char *prop);
JSValue JS_GetPropertyUint32(JSContext *ctx, JSValue obj, uint32_t idx);
int JS_SetProperty(JSContext *ctx, JSValue obj, JSAtom prop, JSValue val);
int JS_SetPropertyStr(JSContext *ctx, JSValue obj, const char *prop, JSValue val);
int JS_SetPropertyUint32(JSContext *ctx, JSValue obj, uint32_t idx, JSValue val);
JSValue JS_GetGlobalObject(JSContext *ctx);

/* Function operations */
JSValue JS_Call(JSContext *ctx, JSValue func, JSValue this_obj, int argc, JSValue *argv);
JSValue JS_CallConstructor(JSContext *ctx, JSValue func, int argc, JSValue *argv);

/* Evaluation */
JSValue JS_Eval(JSContext *ctx, const char *input, size_t input_len, const char *filename, int eval_flags);

/* Atoms */
JSAtom JS_NewAtom(JSContext *ctx, const char *str);
JSAtom JS_NewAtomLen(JSContext *ctx, const char *str, size_t len);
void JS_FreeAtom(JSContext *ctx, JSAtom v);
void JS_FreeAtomRT(JSRuntime *rt, JSAtom v);

/* Exception handling */
JSValue JS_GetException(JSContext *ctx);
void JS_ResetUncatchableError(JSContext *ctx);

/* Module loading */
typedef JSValue JSModuleLoaderFunc(JSContext *ctx, const char *module_name, void *opaque);
typedef JSModuleNormalizeFunc(JSContext *ctx, const char *module_base_name, const char *module_name, void *opaque);
void JS_SetModuleLoaderFunc(JSRuntime *rt, JSModuleNormalizeFunc *module_normalize, JSModuleLoaderFunc *module_loader, void *opaque);

/* Standard library */
void js_std_init_handlers(JSRuntime *rt);
void js_std_free_handlers(JSRuntime *rt);
void js_std_add_helpers(JSContext *ctx, int argc, const char **argv);
void js_std_loop(JSContext *ctx);
int js_std_init_module(JSContext *ctx, const char *module_name);

/* Promise handling */
void JS_SetHostPromiseRejectionTracker(JSRuntime *rt, void *cb, void *opaque);

/* Memory stats */
typedef struct JSMemoryUsage {
    int64_t malloc_size;
    int64_t malloc_count;
    int64_t memory_used_size;
} JSMemoryUsage;
void JS_ComputeMemoryUsage(JSRuntime *rt, JSMemoryUsage *s);
int64_t JS_GetMemoryUsage(JSRuntime *rt);

/* C function definition */
typedef JSValue JSCFunction(JSContext *ctx, JSValue this_val, int argc, JSValue *argv);
typedef JSValue JSCFunctionMagic(JSContext *ctx, JSValue this_val, int argc, JSValue *argv, int magic);

JSValue JS_NewCFunction(JSContext *ctx, JSCFunction *func, const char *name, int length);
JSValue JS_NewCFunctionMagic(JSContext *ctx, JSCFunctionMagic *func, const char *name, int length, int cproto, int magic);

/* JSON */
JSValue JS_ParseJSON(JSContext *ctx, const char *buf, size_t buf_len, const char *filename);
JSValue JS_JSONStringify(JSContext *ctx, JSValue obj, JSValue replacer, JSValue space);

/* Class ID */
typedef uint32_t JSClassID;
#define JS_INVALID_CLASS_ID 0

typedef struct JSClassDef {
    const char *class_name;
    void (*finalizer)(JSRuntime *rt, JSValue val);
    void (*gc_mark)(JSRuntime *rt, JSValue val, void *mark_func);
} JSClassDef;

int JS_NewClass(JSRuntime *rt, JSClassID class_id, const JSClassDef *class_def);
JSClassID JS_NewClassID(JSClassID *pclass_id);
JSValue JS_NewObjectClass(JSContext *ctx, JSClassID class_id);
void *JS_GetOpaque(JSValue obj, JSClassID class_id);
void *JS_GetOpaque2(JSContext *ctx, JSValue obj, JSClassID class_id);
void JS_SetOpaque(JSValue obj, void *opaque);

/* Reference counting */
#define JS_DupValue(ctx, v) (v)
#define JS_DupValueRT(rt, v) (v)

#ifdef __cplusplus
}
#endif

#endif /* QUICKJS_H */
