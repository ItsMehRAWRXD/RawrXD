#include "rawrxd_moe_geometry.hpp"
#include <cassert>
#include <iostream>
int main() {
 using namespace rawrxd::moe;
 // Synthetic layout only: test the validator, not Nemotron's actual tensor contract.
 ExpertTensor t{"synthetic.experts",{2048,1024,368},{64,36},0};
 t.availableBytes=checkedMul(checkedMul(rowBytes(2048,t.quant),1024),368);
 auto v=selectExpert(t,236,2048,1024);
 assert(v.bytes==1179648 && v.offsetBytes==236*1179648ULL);
 bool rejected=false;
 try { (void)selectExpert(t,236,2048,4096); }
 catch(const std::invalid_argument&) {rejected=true;}
 assert(rejected);
 std::cout<<"MOE_GEOMETRY_TEST=PASS\n";
}
