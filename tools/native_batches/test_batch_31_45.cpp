#include "native_agent_batch_31_45.hpp"
#include <atomic>
#include <filesystem>
#include <iostream>
#include <stdexcept>
using namespace RawrXD::NativeBridge;
static void check(bool b,const char* m){if(!b)throw std::runtime_error(m);}
int main(){
 try{
 Task a{"a","echo",{"hello"},{}},b{"b","echo",{"world"},{"a"}},c{"c","echo",{"!"},{"b"}};
 std::vector<Task> tasks{c,b,a};
 check(!canonicalTask(a).empty(),"31");
 check(taskFingerprint(a).size()==16&&taskFingerprint(a)!=taskFingerprint(b),"32");
 check(validateTaskIds(tasks).ok&&!validateTaskIds({a,a}).ok,"33");
 check(validateTaskArguments(a,1,5).ok&&!validateTaskArguments(a,1,4).ok,"34");
 std::string error;
 auto closure=dependencyClosure(tasks,"c",error);check(closure.size()==2&&closure[0]=="a"&&closure[1]=="b","35");
 auto waves=executionWaves(tasks,error);check(waves.size()==3&&waves[0][0]=="a","36");
 ExecutionReceipt receipt{"a","echo",taskFingerprint(a),fnv1a64("hello"),"",true};
 auto wire=serializeReceipt(receipt);check(!wire.empty(),"37");
 auto parsed=parseReceipt(wire);check(parsed&&parsed->success&&parsed->taskId=="a"&&!parseReceipt("R1broken"),"38");
 auto path=std::filesystem::temp_directory_path()/"rawrxd-batch-31-45-journal.log";
 std::filesystem::remove(path);ReceiptStore store(path);check(store.append(receipt,error),"39 append");
 auto rows=store.read(error);check(rows.size()==1&&rows[0].taskId=="a","39 read");
 check(verifyReceiptChain(rows).ok&&!verifyReceiptChain({receipt,receipt}).ok,"40");
 ToolRegistry registry;
 check(registry.registerTool("echo",[](const auto& args,const auto&)->Result{return {true,args.at(0),{}};}),"registry");
 ToolPolicy policy;check(policy.allow("echo"),"policy");AuditLog audit;ControlledTools tools(registry,policy,audit);
 std::atomic<bool> cancel{false};ExecutionReceipt out;
 auto result=runChecked(a,tools,cancel,out);check(result.ok&&out.success&&out.outputHash==fnv1a64("hello"),"41");
 std::vector<ExecutionReceipt> receipts;
 check(runWave(tasks,tools,cancel,receipts).ok&&receipts.size()==3,"42");
 check(validateOutput(result,5).ok&&!validateOutput(result,4).ok,"43");
 check(checkExpectedText(result,"hello").ok&&!checkExpectedText(result,"wrong").ok,"44");
 auto report=summarize(receipts,3);check(report.complete&&report.succeeded==3&&report.failed==0,"45");
 std::filesystem::remove(path);
 std::cout<<"BATCH_31_45_PASS\n";
 return 0;
 }catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}
}
