/*
 * QuickJS libregexp - Minimal stub implementation
 */

#include "quickjs.h"
#include <stdlib.h>
#include <string.h>

/* Regex pattern structure */
typedef struct JSRegExp {
    char *pattern;
    int flags;
} JSRegExp;

/* Compile a regex pattern */
JSRegExp *JS_CompileRegExp(const char *pattern, size_t len, int flags) {
    (void)len;
    JSRegExp *re = (JSRegExp *)malloc(sizeof(JSRegExp));
    if (!re) return NULL;
    re->pattern = strdup(pattern);
    re->flags = flags;
    return re;
}

/* Free a compiled regex */
void JS_FreeRegExp(JSRegExp *re) {
    if (re) {
        free(re->pattern);
        free(re);
    }
}

/* Execute a regex match */
int JS_ExecRegExp(JSContext *ctx, JSRegExp *re, const char *str, size_t len, int *captures, int max_captures) {
    (void)ctx;
    (void)re;
    (void)str;
    (void)len;
    (void)captures;
    (void)max_captures;
    return -1; /* No match */
}

/* Test if a string matches a regex */
int JS_TestRegExp(JSContext *ctx, JSRegExp *re, const char *str, size_t len) {
    (void)ctx;
    (void)re;
    (void)str;
    (void)len;
    return 0; /* No match */
}

/* Get regex source */
const char *JS_GetRegExpSource(JSRegExp *re) {
    return re ? re->pattern : "";
}

/* Get regex flags */
int JS_GetRegExpFlags(JSRegExp *re) {
    return re ? re->flags : 0;
}
