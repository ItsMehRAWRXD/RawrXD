/* ss_evidence.h — non-arch evidence helpers (hash/barrier/copy/oracle/gate) */
#ifndef SS_EVIDENCE_H
#define SS_EVIDENCE_H
#include <stdint.h>
typedef struct {
    const char *name;
    uint64_t abs_off, bytes, dim0, dim1;
    uint32_t codec;
    uint64_t hash;
} SsTensorId;
uint64_t ss_tensor_id_hash(const SsTensorId *t);
void ss_tensor_id_print(const SsTensorId *t, const char *when);
int ss_tensor_id_check(const SsTensorId *t, uint64_t expect);
void ss_barrier_reset(void);
uint32_t ss_barrier_note(const char *producer, const char *consumer);
uint32_t ss_barrier_seq(void);
void ss_copy_reset(void);
void ss_copy_add_host(uint64_t n);
void ss_copy_add_d3d_upload(uint64_t n);
void ss_copy_add_vk_readback(uint64_t n);
void ss_copy_print(void);
int ss_q6k_row_oracle(const char *shard);
int ss_geo_indep_output_weight(const char *shard);
int ss_rms_oracle(const float *x, const float *w, const float *y_gpu, uint32_t n, float eps);
int ss_gate_reconcile(uint64_t deep2_status, uint64_t phase_rc,
                      int model_op, int block_op, int math_obs);
#endif
