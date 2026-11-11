#include "deep2_snap.hpp"
#include <cassert>
#include <iostream>
using namespace deep2::snap;
int main(){
 {Controller c;std::string s="TOOL read 12\ntest/foo.cpp\nEND_TOOL\n";Result r;for(char ch:s){r=c.on_token(std::string_view(&ch,1));if(r.reason!=Reason::none)break;}assert(r.reason==Reason::tool_ready);assert(r.command->payload=="test/foo.cpp");}
 {Controller c;auto r=c.on_token("TOOL finish 0\n\nEND_TOOL\n");assert(r.reason==Reason::finish);}
 {Controller c;auto r=c.on_token("TOOL shell 0\n");assert(r.reason==Reason::invalid);}
 {Controller c;auto r=c.on_token("TOOL read 3\nabc\nEND_TOOL\n");assert(r.reason==Reason::tool_ready);}
 {Controller c;auto r=c.on_token("TOOL read 2\nabc");assert(r.reason==Reason::invalid);}
 {Controller c; c.cancel();auto r=c.before_decode();assert(r.reason==Reason::cancelled);}
 {Limits l;l.max_tokens=1;Controller c(l);assert(c.on_token("x").reason==Reason::none);assert(c.before_decode().reason==Reason::token_limit);}
 std::cout<<"SNAP_TESTS_PASS\n";
}
