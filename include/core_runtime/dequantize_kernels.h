#ifndef RAWRXD_CORE_DEQUANTIZE_KERNELS_H
#define RAWRXD_CORE_DEQUANTIZE_KERNELS_H
#include "core_export.h"
namespace RawrXD { namespace Core {
RAWRXD_CORE_EXPORT void DequantizeQ4_0(const void* input, float* output, int n);
RAWRXD_CORE_EXPORT void DequantizeQ8_0(const void* input, float* output, int n);
}} // namespace RawrXD::Core
#endif // RAWRXD_CORE_DEQUANTIZE_KERNELS_H
