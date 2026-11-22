#include "deep2/ReapQuantRange.hpp"
#include <cstdio>
#include <sstream>
using namespace Deep2::ReapQuant;
int main(){
    int pass=0,fail=0;auto check=[&](bool ok,const char* name){std::printf("%s %s\n",ok?"PASS":"FAIL",name);ok?++pass:++fail;};
    Q4Block source{};StoreHalf(source.data(),0x3c00);
    for(unsigned i=4;i<16;++i)source[i]=1;
    for(unsigned i=16;i<144;++i)source[i]=static_cast<uint8_t>(i);
    std::string raw(reinterpret_cast<const char*>(source.data()),source.size()),many;
    for(unsigned i=0;i<257;++i)many+=raw;
    std::istringstream in(many);std::ostringstream out;RangeStats stats;
    check(ConvertRange(in,out,many.size(),stats)&&stats.blocks==257&&out.str().size()==257*Q2Bytes,"multi-batch exact size");
    Q2Block expected{};Error err;Convert(source,expected,err);
    const std::string block(reinterpret_cast<const char*>(expected.data()),expected.size());
    check(out.str().substr(256*Q2Bytes)==block&&out.str().substr(0,Q2Bytes)==block,"first and final block match codec");
    check(std::abs(stats.squared-257*err.squared)<1e-8&&std::abs(stats.signal-257*err.signal)<1e-8,"measured aggregate error");
    check(std::isfinite(stats.RelativeRmse())&&stats.RelativeRmse()>0,"relative reconstruction metric");
    std::istringstream shortInput(raw);std::ostringstream bad;const auto saved=stats;
    check(!ConvertRange(shortInput,bad,2*Q4Bytes,stats)&&stats.blocks==saved.blocks&&bad.str().empty(),"truncated batch rejected");
    std::istringstream input(raw);check(!ConvertRange(input,bad,Q4Bytes-1,stats),"partial block rejected");
    std::ostringstream closed;closed.setstate(std::ios::badbit);check(!ConvertRange(input,closed,Q4Bytes,stats)&&stats.blocks==saved.blocks,"write failure retains prior stats");
    StoreHalf(source.data(),0x7c00);std::string invalid(reinterpret_cast<const char*>(source.data()),source.size());
    std::istringstream nonfinite(invalid);check(!ConvertRange(nonfinite,bad,Q4Bytes,stats)&&stats.blocks==saved.blocks,"invalid block rejected");
    check(RangeStats{}.RelativeRmse()==0,"zero signal zero error");
    std::printf("PASS_COUNT=%d FAIL_COUNT=%d\n",pass,fail);return fail?1:0;
}
