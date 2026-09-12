/* ss_vk_block_util.h */
#ifndef SS_VK_BLOCK_UTIL_H
#define SS_VK_BLOCK_UTIL_H
#include "ss_vk_api.h"
uint32_t ss_vk_codec_ty(uint32_t c);
int ss_vk_upload(SsVk *v, const void *host, uint64_t n, VkBuffer *b, VkDeviceMemory *m);
int ss_vk_fin_obs(SsVk *v, VkDeviceMemory mem, uint32_t n, int *ok);
void ss_vk_dropb(SsVk *v, VkBuffer *b, VkDeviceMemory *m);
#endif
