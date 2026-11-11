#include "native_agent_batch_46_60.hpp"
#include <iostream>
#include <stdexcept>
using namespace RawrXD::NativeBridge;
static void check(bool b,const char* msg){if(!b)throw std::runtime_error(msg);}
int main(){try{
RunConfig config;config.permittedTools={"echo"};
check(validateRunConfig(config).ok,"46");
std::vector<Task> tasks={{"a","echo",{"hello"},{}},{"b","echo",{"world"},{"a"}}};
check(preflightTasks(tasks,config).ok,"47");
std::string err;check(rootsOf(tasks,err)==std::vector<std::string>{"a"},"48");
check(dependentsOf(tasks,"a",err)==std::vector<std::string>{"b"},"49");
ExecutionReceipt failed;failed.taskId="a";failed.tool="echo";failed.success=false;
check(terminalFailures({failed})==std::vector<std::string>{"a"},"50");
check(!validateReceiptsAgainstTasks(tasks,{failed}).ok,"51");
check(renderExecutionReport(tasks,{}).find("planned=2")!=std::string::npos,"52");
check(!verifyExpectedFingerprints({failed},{{"a","different"}}).ok,"53");
ToolRegistry registry;check(registry.registerTool("echo",[](const auto& args,const auto&)->Result{return {true,args.at(0),{}};}),"registry");
ToolPolicy policy;check(policy.allow("echo"),"policy");AuditLog audit;ControlledTools tools(registry,policy,audit);
std::atomic<bool> cancel{false};ExecutionReceipt receipt;
check(guardedRun(tasks[0],config,tools,cancel,receipt).ok&&receipt.success,"54");
std::vector<ExecutionReceipt> receipts;check(guardedPlanRun(tasks,config,tools,cancel,receipts).ok&&receipts.size()==2,"55");
check(validateNoDuplicateReceipts(receipts).ok&& !validateNoDuplicateReceipts({receipts[0],receipts[0]}).ok,"56");
check(pendingTaskIds(tasks,{receipts[0]})==std::vector<std::string>{"b"},"57");
check(verifyCompletedPlan(tasks,receipts).ok,"58");
check(escapeLogField("a\nb")=="a\\nb","59");
check(diagnosticLine(receipts[0]).find("PASS")!=std::string::npos,"60");
std::cout<<"BATCH_46_60_PASS\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
