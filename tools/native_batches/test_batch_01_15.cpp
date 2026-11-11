#include "native_agent_batch.hpp"
#include <atomic>
#include <filesystem>
#include <iostream>
#include <stdexcept>
using namespace RawrXD::NativeBridge;
static void require(bool b,const char* m){if(!b)throw std::runtime_error(m);}
int main(){
 try{
 std::atomic<bool> cancel{false};
 ToolRegistry registry;
 require(registry.registerTool("echo",[](const auto& a,const auto&)->Result{return {true,a.empty()?"":a[0],{}};}),"registry");
 AuditLog audit;ToolPolicy policy;ControlledTools tools(registry,policy,audit);
 require(!tools.invoke("echo",{"hello"},cancel).ok,"1 deny by default");
 require(policy.allow("echo") && tools.invoke("echo",{"hello"},cancel).ok,"2 allow");
 require(audit.snapshot().size()==2,"3 audit");
 require(Budget{1,3}.permits(1,3) && !Budget{1,3}.permits(2,3),"4 budget");
 int attempts=0;auto retry=Retry::execute([&]()->Result{++attempts;return {attempts==2,"ok",{}};},3,cancel);
 require(retry.ok && attempts==2,"5 retry");
 auto root=std::filesystem::temp_directory_path()/"rawrxd-native-batch-tests";
 std::filesystem::create_directories(root);
 std::string err;
 Journal journal(root/"journal.log");require(journal.append("entry",err),"6 journal append");
 require(!journal.read(err).empty(),"7 journal read");
 EvidenceLedger ledger;ledger.add("a",{true,"yes",{}});require(ledger.snapshot().size()==1,"8 ledger");
 std::vector<Task> deps={{"b","echo",{},{"a"}},{"a","echo",{}, {}}};
 require(DependencyGraph::validate(deps).ok,"9 graph validation");
 auto order=DependencyGraph::order(deps,err);require(order.size()==2&&order[0]=="a","10 graph order");
 deps[1].dependencies={"b"};require(!DependencyGraph::validate(deps).ok,"11 cycle");
 WorkQueue queue;require(queue.push({"a","echo",{}, {}})&&!queue.push({"a","echo",{}, {}})&&queue.pop().has_value(),"12 queue");
 NativeSession session({1,3});require(session.run({"a","echo",{"hi"},{}},tools,cancel).ok,"13 session");
 require(!session.run({"b","echo",{"hi"},{}},tools,cancel).ok,"13 budget enforced");
 auto file=writeFileAtomic(root,"batch_new.txt","alpha\nbeta\n");
 require(file.ok,"14 write");
 require(compareFile(root,"batch_new.txt","alpha\nbeta\n").ok,"14 compare");
 require(searchText(root,"batch_new.txt","beta").output.find("2:beta")!=std::string::npos,"14 search");
 require(!writeFileAtomic(root,"../escape.txt","bad").ok,"14 confinement");
 require(formatFIM("a","b","fim").ok && !formatFIM("a","b","unknown").ok,"15 FIM");
 require(!invokeInference({},"x",cancel).ok,"15 fail closed inference");
 std::filesystem::remove_all(root);
 std::cout<<"BATCH_01_15_PASS\n";
 return 0;
 }catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}
}
