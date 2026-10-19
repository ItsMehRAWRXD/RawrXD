#ifndef BS_COMMON_H
#define BS_COMMON_H
#include <stdint.h>
#include <stddef.h>
#define BS_PATH_MAX 1024
#define BS_LINE_MAX 4096
typedef struct BsState {
    uint32_t pid;
    int pid_alive;
    int vendor_smoke_pass;
    int local_smoke_pass;
    int cert_binary_touched;
    int merge_deferred;
    int promote;
    int highest_pos;
    int sealed_reuse_seen;
    int terminal_pass_seen;
    int terminal_fail_seen;
    uint64_t forward_calls;
    uint64_t full_block_calls;
    uint64_t commit_calls;
    uint64_t advance_calls;
    uint64_t generated_tokens;
    char cert_sha256_expected[65];
    char cert_sha256_observed[65];
    char last_stop_reason[128];
} BsState;
#endif
