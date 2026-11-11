#!/usr/bin/env python3
import tempfile
from pathlib import Path
from patch_numeric import patch_executor, patch_token0, write_safe

executor='''// all paths good for embedding and dot rows
output[j] = weight[j * out + token];
sum += double(input[j]) * double(weight[j * out + i]);
'''
corrected,changed,notes=patch_executor(executor)
assert changed and all('CORRECTED' in n for n in notes)
assert 'weight[token * in + j]' in corrected and 'weight[i * in + j]' in corrected
second,again,notes2=patch_executor(corrected)
assert second == corrected and not again
print('EXECUTOR_PATCH=PASS IDEMPOTENT=PASS')

s='''#include <cstdint>
#include <vector>
static void MatMul(const float* A, const float* B, float* C, int M, int K, int N)
{
#pragma omp parallel for collapse(2)
    for (int i = 0; i < M; ++i)
      for (int j = 0; j < N; ++j) {
       __m512 s = _mm512_setzero_ps();
       for (int k = 0; k < K; ++k) { C[0] += B[k * N + j]; }
       for (int k = 0; k < K; ++k) C[0] += B[k * N + j];
       // original SIMD pointer bug:
       auto x = B + k * N + j;
      }
}
static void VecAdd(float* out,const float* a,const float* b,int n){}
// elsewhere
case ModelGenie::GGMLType::Q6_K:
{
 struct Q6KBlock { uint8_t ql[128]; uint8_t qh[64]; uint16_t scales[8]; uint16_t d; };
 for(int j=0;j<256;++j) { uint8_t lo=src[0].ql[j/2]; out[j]=lo; }
 break;
}
        default:
 break;
'''
t,f,notes=patch_token0(s)
assert f and 'int8_t scales[16]' in t and 'const float* b = B + size_t(j) * K;' in t
assert 'RAWRXD_Q6_SIGNED_SCALES_002' in t
again,f2,n2=patch_token0(t)
assert not f2 and again==t
print('TOKEN0_PATCH=PASS IDEMPOTENT=PASS')

with tempfile.TemporaryDirectory() as d:
 p=Path(d)/'executor.cpp';p.write_text(executor)
 status,notes=write_safe(p,patch_executor,False)
 assert status and p.read_text()==executor
 assert not p.with_name(p.name+'.pre_numerical_parity.bak').exists()
 status,notes=write_safe(p,patch_executor,True)
 assert status and p.with_name(p.name+'.pre_numerical_parity.bak').exists()
 assert p.read_text()!=executor
 status,notes=write_safe(p,patch_executor,True)
 assert not status
 print('DRY_RUN_NO_MODIFICATION=PASS BACKUP_PRESERVED=PASS')
 try:
  patch_executor('wrong source')
 except ValueError: print('UNKNOWN_SOURCE_FAIL_CLOSED=PASS')
 else:raise AssertionError('unexpected acceptance of unknown executor')
