/* ss_model_plan_io.h — shared GGUF IO for plan meta/bind (internal) */
#ifndef SS_MODEL_PLAN_IO_H
#define SS_MODEL_PLAN_IO_H
#include "ss_model_plan.h"
#include "ss_tensor_roles.h"
#include <stdio.h>
typedef struct { char name[160]; uint64_t rel, dims[4], elems; uint32_t ty, nd; } SsPlanEnt;
int ss_mp_rd(FILE *f, void *p, size_t n);
int ss_mp_sk(FILE *f, int64_t n);
int ss_mp_rstr(FILE *f, char *buf, size_t cap);
int ss_mp_skip_val_t(FILE *f, uint32_t t);
int ss_mp_kv_u32(FILE *f, uint32_t t, uint32_t *o);
int ss_mp_kv_f32(FILE *f, uint32_t t, float *o);
int ss_mp_ends_key(const char *k, const char *suf);
uint32_t ss_mp_map_codec(uint32_t ty);
void ss_mp_fill_ref(SsTensorRef *r, const SsPlanEnt *e, uint64_t base, uint64_t bytes,
                    uint32_t shard_index);
SsTensorRef *ss_mp_role_slot(SsBlockPlan *b, SsTensorRole role);
int ss_mp_bind_tensors(SsModelPlan *out, SsPlanEnt *e, uint32_t nt, uint64_t base,
                       uint32_t shard_index, int allow_meta_overwrite);
int ss_mp_bind_tensors_fs(SsModelPlan *out, SsPlanEnt *e, uint32_t nt, uint64_t base,
                          uint32_t shard_index, uint64_t file_size);
int ss_mp_read_meta(FILE *f, SsModelPlan *out, char *arch, uint32_t *align,
                    uint64_t *nt, int read_meta);
int ss_mp_build_one(SsModelPlan *out, const char *path, uint32_t shard_index, int read_meta);
#endif
