#include "context_gpu.hpp"
#include <cassert>
#include <iostream>
int main(){
 using namespace deep2;
 Geometry q; q.layers=28;q.kv_heads=2;q.key_dim=128;q.value_dim=128;q.max_validated_positions=1000000;
 auto c=estimate_kv(q,1000000,KvFormat::INT8,16ull<<30,1ull<<30);
 assert(c.bytes_per_token==14336); assert(c.fits);
 auto p=plan_context(q,1000000,KvFormat::INT8,2ull<<30,30ull<<30,16ull<<30,1ull<<30);
 assert(p.mode==PlacementMode::ModelPlusContext);
 auto bad=plan_context(q,1000000,KvFormat::FP16,2ull<<30,30ull<<30,16ull<<30,1ull<<30);
 assert(bad.mode==PlacementMode::TieredContext);
 bool rejected=false;try { ContextSession s(q,{}); }catch(const std::invalid_argument&){rejected=true;} assert(rejected);
 std::cout<<"CAPACITY_TEST_PASS bytes_per_token="<<c.bytes_per_token<<" required="<<c.required_bytes<<"\n";
}
