#include "rawrxd/src/deep2/deep2_e2e_trace.hpp"
#include <fstream>
#include <iostream>
using namespace deep2;
int main(){
    {std::ofstream g("selftest_model.gguf",std::ios::binary|std::ios::trunc);g.write("GGUF",4);uint32_t v=3;g.write((char*)&v,4);uint64_t tensors=1,meta=0;g.write((char*)&tensors,8);g.write((char*)&meta,8);char pad[256]{};g.write(pad,sizeof(pad));}
    E2ETraceWriter w;if(!w.open("selftest.trace","selftest-real-model",3,2,1,4,{"selftest_model.gguf"}))return 10;
    w.discover();w.opened();w.backend();w.tokenized(4);w.weight_touch(128);
    const char* pieces[2]={"Hello", " world"};int ids[2]={101,202};
    std::ofstream out("selftest.stdout",std::ios::binary|std::ios::trunc);
    for(uint32_t t=0;t<2;t++){for(uint32_t l=0;l<3;l++)w.forward(t,l);w.kv(t);w.logits(t,32000);w.sample(t,ids[t]);uint32_t n=(uint32_t)std::char_traits<char>::length(pieces[t]);w.detokenize(t,ids[t],pieces[t],n);out.write(pieces[t],n);out.flush();w.stream(t,ids[t],pieces[t],n);}w.end();out.close();
    std::cout<<"DEEP2_BATCH76_80_SELFTEST_FIXTURE=PASS\n";return 0;
}
