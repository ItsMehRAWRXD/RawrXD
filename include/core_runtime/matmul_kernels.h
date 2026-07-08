#ifndef RAWRXD_CORE_MATMUL_KERNELS_H
#define RAWRXD_CORE_MATMUL_KERNELS_H
#include "core_export.h"
namespace RawrXD { namespace Core {
RAWRXD_CORE_EXPORT void MatMulAVX512(const float* a, const float* b, float* c, int m, int n, int k);
RAWRXD_CORE_EXPORT void MatMulAVX2(const float* a, const float* b, float* c, int m, int n, int k);
}} // namespace RawrXD::Core
#endif // RAWRXD_CORE_MATMUL_KERNELS_H
