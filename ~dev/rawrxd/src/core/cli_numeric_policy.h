#ifndef RAWRXD_CLI_NUMERIC_POLICY_H
#define RAWRXD_CLI_NUMERIC_POLICY_H
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>

static inline int rawrxd_parse_u32_range(const char* text, uint32_t minimum,
                                         uint32_t maximum, uint32_t* out) {
    if (!text || !*text || !out || text[0] < '0' || text[0] > '9') return 0;
    errno = 0;
    char* end = NULL;
    unsigned long value = strtoul(text, &end, 10);
    if (errno == ERANGE || end == text || *end != '\0' ||
        value < minimum || value > maximum) return 0;
    *out = (uint32_t)value;
    return 1;
}

static inline int rawrxd_parse_f32_range(const char* text, double minimum,
                                         double maximum, float* out) {
    if (!text || !*text || !out ||
        (text[0] != '-' && text[0] != '+' && text[0] != '.' &&
         (text[0] < '0' || text[0] > '9'))) return 0;
    errno = 0;
    char* end = NULL;
    double value = strtod(text, &end);
    if (errno == ERANGE || end == text || *end != '\0' ||
        !isfinite(value) || value < minimum || value > maximum) return 0;
    *out = (float)value;
    return 1;
}
#endif
