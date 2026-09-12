/* ss_vk_ops.h — shared RMSNorm/GEMV dispatch on SsVk */
#ifndef SS_VK_OPS_H
#define SS_VK_OPS_H
#include "ss_vk_api.h"
int ss_vk_op_rms(SsVk *v, VkBuffer inb, VkBuffer wb, uint64_t wbytes, VkBuffer outb, uint32_t n);
int ss_vk_op_gemv(SsVk *v, VkBuffer wb, uint64_t wbytes, VkBuffer xb, VkBuffer yb,
                  uint32_t rows, uint32_t cols, uint32_t codec);
int ss_vk_op_gemv_n(SsVk *v, VkBuffer wb, uint64_t wbytes, VkBuffer xb, VkBuffer yb,
                    uint32_t rows, uint32_t cols, uint32_t codec, uint32_t nrows);
int ss_vk_op_gemv_tile(SsVk *v, VkBuffer wb, uint64_t w_off, uint64_t w_bytes,
                       VkBuffer xb, VkBuffer yb, uint64_t y_off,
                       uint32_t nrows, uint32_t cols, uint32_t codec);
int ss_vk_lm_row_ladder(SsVk *v, VkBuffer ww, uint64_t wbytes, uint32_t rows,
                        uint32_t cols, uint32_t codec);
int ss_vk_lm_tiled_gemv(SsVk *v, VkBuffer ww, uint64_t wbytes, uint32_t rows,
                        uint32_t cols, uint32_t codec, uint32_t tile);
#endif
