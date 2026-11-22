#include "reap/ReapGraphCompile.hpp"
#include <cstdio>
using namespace reap;
int main() {
    int pass=0,fail=0;
    auto check=[&](bool ok,const char* name){std::printf("%s %s\n",ok?"PASS":"FAIL",name);ok?++pass:++fail;};
    auto rejects=[&](const char* name,auto f){try{f();check(false,name);}catch(const std::exception&){check(true,name);}};
    ModelGeometry g;g.architecture="inkling2_loop";g.blockCount=24;g.loopCount=3;g.loopStart=6;g.loopEnd=18;
    std::vector<PhysicalTensor> tensors;
    for(unsigned i=0;i<24;++i){PhysicalTensor t;t.name="blk."+std::to_string(i)+".weight";t.family="attention_q";t.dims={i+1};tensors.push_back(t);}
    PhysicalTensor global;global.name="token_embd.weight";global.family="embedding";global.dims={100};tensors.push_back(global);
    const auto ir=BuildCanonicalIR(g,tensors);const auto plan=CompileGraph(ir);
    check(ir.tensors.size()==25 && plan.visits.size()==50,"full topology with unchanged physical tensors");
    check(plan.physicalParamCount==400,"physical count");
    // 7+...+19 = 169, repeated twice in addition to the base traversal.
    check(plan.logicalParamCount==738,"logical count includes both boundary layers and suffix");
    bool ops=true;std::vector<unsigned> counts(24);
    for(const auto& vp:plan.visits){ops=ops && vp.ops.size()==1 && vp.ops.front().physicalTensorIndex==vp.visit.physicalLayer;++counts.at(vp.visit.physicalLayer);}
    check(ops,"each visit references original physical weight");
    bool multiplicity=true;for(size_t i=0;i<counts.size();++i)multiplicity=multiplicity&&counts[i]==(i>=6&&i<=18?3u:1u);
    check(multiplicity,"all layers covered exactly as expected");
    check(plan.preamble.size()==1&&plan.preamble.front().physicalTensorIndex==24,"global embedding once");
    auto bad=ir;bad.visits.front().physicalLayer=24;rejects("invalid scheduled layer",[&]{CompileGraph(bad);});
    bad=ir;bad.tensors.front().layerIndex=24;rejects("invalid tensor layer",[&]{CompileGraph(bad);});
    PhysicalTensor huge;huge.dims={UINT64_MAX,2};rejects("parameter multiplication overflow",[&]{TensorParamCount(huge);});
    bad=ir;bad.tensors.front().dims={UINT64_MAX};rejects("physical sum overflow",[&]{CompileGraph(bad);});
    bad=ir;bad.tensors[6].dims={UINT64_MAX/2};rejects("logical sum overflow",[&]{CompileGraph(bad);});
    std::printf("%d passed, %d failed\n",pass,fail);return fail?1:0;
}
