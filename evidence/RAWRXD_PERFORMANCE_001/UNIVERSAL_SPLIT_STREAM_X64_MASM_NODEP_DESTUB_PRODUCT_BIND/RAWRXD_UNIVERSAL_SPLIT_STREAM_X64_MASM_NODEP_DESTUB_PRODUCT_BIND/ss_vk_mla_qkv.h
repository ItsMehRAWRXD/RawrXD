/* ss_vk_mla_qkv.h — run block MLA to host Q/KV floats */
#ifndef SS_VK_MLA_QKV_H
#define SS_VK_MLA_QKV_H
#include "ss_vk_api.h"
#include "ss_model_plan.h"
int ss_vk_mla_qkv_host(SsVk *v, const SsModelPlan *plan, uint32_t block,
                       float **q_out, uint32_t *q_n,
                       float **kv_out, uint32_t *kv_n);
#endif
