/* ss_vk_ops.h — shared RMSNorm/GEMV dispatch on SsVk */
#ifndef SS_VK_OPS_H
#define SS_VK_OPS_H
#include "ss_vk_api.h"
int ss_vk_op_rms(SsVk *v, VkBuffer inb, VkBuffer wb, uint64_t wbytes, VkBuffer outb, uint32_t n);
int ss_vk_op_gemv(SsVk *v, VkBuffer wb, uint64_t wbytes, VkBuffer xb, VkBuffer yb,
                  uint32_t rows, uint32_t cols, uint32_t codec);
#endif
