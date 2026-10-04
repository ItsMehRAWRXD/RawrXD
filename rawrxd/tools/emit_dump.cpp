#include "PolyKernel.hpp"
#include "QuantKernelRegistry.hpp"
#include <cstdio>
using namespace Deep2; using namespace Deep2::poly;
int main(){
  auto& r = QuantKernelRegistry::Instance(); r.Initialize(); r.ProbeCPU();
  auto hw = describeHardware();
  KernelRequest q; q.op=PolyOp::GEMV; q.M=64; q.N=512; q.K=512; q.quantType=0;
  auto pl = planGEMV(q, hw);
  auto b = emitX64(pl.ir, q, hw);
  std::printf("OK=%d BYTES=%zu\n", b.ok, b.bytes.size());
  for (size_t i=0;i<b.bytes.size();++i){
    std::printf("%02X ", b.bytes[i]);
    if ((i%8)==7) std::printf("\n");
  }
  std::printf("\n");
  return 0;
}
