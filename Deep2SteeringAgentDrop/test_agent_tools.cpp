#include "Deep2AgentTools.hpp"
#include "Deep2Interventions.hpp"
#include <cassert>
#include <iostream>
using namespace rawrxd::deep2;
int main(){
    auto x=json::parse("{\"s\":\"a\\nb\",\"n\":12,\"ok\":true}");
    assert(x.get("s")->str=="a\nb");assert(json::parse(json::dump(x)).get("n")->number==12);
    bool bad=false;try{json::parse("{\"x\":1,\"x\":2}");}catch(...){bad=true;}assert(bad);
    bad=false;try{json::parse("{\"x\":\"unterminated}");}catch(...){bad=true;}assert(bad);
    ToolRegistry registry;
    assert(registry.Register({"file_reader","read workspace file",{{"path",json::Value::String,true}}},
        [](const ToolCall& c){ToolObservation o;o.ok=true;o.output="contents:"+c.args.get("path")->str;return o;}));
    auto call=ParseToolCall(R"({"tool_calls":[{"id":"call_1","type":"function","function":{"name":"file_reader","arguments":"{\"path\":\"test_hello.py\"}"}}]})");
    assert(call.name=="file_reader");auto o=registry.Dispatch(call);assert(o.ok&&o.output=="contents:test_hello.py");
    auto wrong=ParseToolCall(R"({"name":"file_reader","arguments":{"other":"x"}})");
    assert(!registry.Dispatch(wrong).ok);assert(!registry.Dispatch({"","no_such_tool",json::Value::obj()}).ok);
    int turns=0;auto result=RunAgent(registry,[&](const std::vector<std::string>& messages){
        if(turns++==0)return AgentStep{false,R"({"name":"file_reader","arguments":{"path":"test_hello.py"}})"};
        assert(messages.back().find("contents:test_hello.py")!=std::string::npos);
        return AgentStep{true,"Read completed"};}, {"user: read test_hello.py"});
    assert(result.ok&&result.answer=="Read completed"&&result.observations.size()==1);
    auto budget=RunAgent(registry,[](const std::vector<std::string>&){return AgentStep{false,R"({"name":"file_reader","arguments":{"path":"x"}})"};},{},1);
    assert(!budget.ok&&budget.error=="TOOL_BUDGET_EXHAUSTED");
    InterventionController ctrl;ctrl.Enable(true);assert(ctrl.Add({InterventionPoint::Residual,1,0.5f,{2.f,4.f}}));
    float v[]={1,2};assert(ctrl.Apply(InterventionPoint::Residual,1,v,2));assert(v[0]==2&&v[1]==4);
    ctrl.CertificationMode(true);assert(ctrl.Apply(InterventionPoint::Residual,1,v,2));assert(v[0]==2);
    ConstrainedGenerator cg({"{\"name\":\"file_reader\"}"});
    std::vector<std::string> pieces={"{","[","\"name\"",":","\"file_reader\"","}"};
    std::vector<float> logits(6,0);assert(cg.Mask(logits,pieces));assert(!std::isfinite(logits[1]));
    for(auto piece:{"{","\"name\"",":","\"file_reader\"","}"})assert(cg.Accept(piece));
    assert(cg.Complete());
    std::cout<<"JSON_SCHEMA=PASS\nTOOL_DISPATCH=PASS\nOBSERVATION_RESUME=PASS\nBOUNDED_LOOP=PASS\nINTERVENTION_BYPASS=PASS\nFINITE_CONSTRAINTS=PASS\n";
}
