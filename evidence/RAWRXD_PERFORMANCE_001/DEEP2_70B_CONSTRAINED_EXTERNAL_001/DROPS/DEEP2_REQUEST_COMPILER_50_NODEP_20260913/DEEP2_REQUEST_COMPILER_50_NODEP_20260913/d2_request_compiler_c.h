#ifndef D2_REQUEST_COMPILER_C_H
#define D2_REQUEST_COMPILER_C_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct d2rc_plan_handle d2rc_plan_handle;

enum d2rc_status {
    D2RC_NOT_RUN = 0,
    D2RC_READY   = 1,
    D2RC_PASS    = 2,
    D2RC_HOLD    = 3,
    D2RC_FAIL    = 4,
    D2RC_SKIPPED = 5
};

d2rc_plan_handle* d2rc_compile(const char* utf8_request);
void d2rc_free(d2rc_plan_handle*);
size_t d2rc_node_count(const d2rc_plan_handle*);
const char* d2rc_node_canonical(const d2rc_plan_handle*, size_t index);
int d2rc_node_status(const d2rc_plan_handle*, size_t index);
int d2rc_mark(d2rc_plan_handle*, uint32_t id, int status);
size_t d2rc_ready_count(const d2rc_plan_handle*);
uint32_t d2rc_ready_id(const d2rc_plan_handle*, size_t index);
const char* d2rc_last_error(const d2rc_plan_handle*);
size_t d2rc_mechanism_count(void);
const char* d2rc_mechanism_name(size_t one_based_index);

#ifdef __cplusplus
}
#endif
#endif
