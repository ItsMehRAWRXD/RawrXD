#include "d2_request_compiler.hpp"
#include <cassert>
#include <iostream>
#include <set>

int main() {
    const char* req =
        "write tokenizer source;\n"
        "build tokenizer source;\n"
        "test tokenizer source;\n"
        "verify tokenizer source;\n"
        "check tokenizer source;\n"
        "commit tokenizer source;\n"
        "push tokenizer source;\n"
        "write tokenizer source;\n";

    auto r=d2rc::compile(req);
    assert(r.ok);
    assert(d2rc::mechanism_count()==50);
    assert(r.plan.duplicate_nodes_eliminated==1);
    assert(r.plan.nodes.size()==7);

    // check should be dominated by verify
    bool sawSkipped=false;
    for(auto& n:r.plan.nodes) if(n.verb=="check") sawSkipped=(n.status==d2rc::Status::Skipped);
    assert(sawSkipped);

    // Initially write must be executable.
    assert(!r.plan.ready.empty());
    uint32_t writeId=0, buildId=0, testId=0, verifyId=0, commitId=0, pushId=0;
    for(auto& n:r.plan.nodes){
        if(n.verb=="write") writeId=n.id;
        if(n.verb=="build") buildId=n.id;
        if(n.verb=="test") testId=n.id;
        if(n.verb=="verify") verifyId=n.id;
        if(n.verb=="commit") commitId=n.id;
        if(n.verb=="push") pushId=n.id;
    }
    assert(writeId && buildId && testId && verifyId && commitId && pushId);

    d2rc::Evidence e;
    e.authority=d2rc::Authority::Measured;
    e.source="selftest";
    e.proof="explicit pass";

    d2rc::mark(r.plan,writeId,d2rc::Status::Pass,&e);
    // Build may be independent in conservative inference; mark it.
    d2rc::mark(r.plan,buildId,d2rc::Status::Pass,&e);
    d2rc::mark(r.plan,testId,d2rc::Status::Pass,&e);
    d2rc::mark(r.plan,verifyId,d2rc::Status::Pass,&e);
    d2rc::mark(r.plan,commitId,d2rc::Status::Pass,&e);
    d2rc::mark(r.plan,pushId,d2rc::Status::Pass,&e);

    std::cout << "DEEP2_REQUEST_COMPILER_50_NODEP_SELFTEST=PASS\n";
    std::cout << "MECHANISMS=" << d2rc::mechanism_count() << "/50\n";
    std::cout << "NODES=" << r.plan.nodes.size() << "\n";
    std::cout << "DUPLICATES_ELIMINATED=" << r.plan.duplicate_nodes_eliminated << "\n";
    std::cout << "DOMINATED_ELIMINATED=" << r.plan.dominated_nodes_eliminated << "\n";
    std::cout << "STATE_HASH=" << r.plan.state_hash << "\n";
    return 0;
}
