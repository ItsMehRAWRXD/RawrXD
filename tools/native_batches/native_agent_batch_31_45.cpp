#include "native_agent_batch_31_45.hpp"
#include <algorithm>
#include <charconv>
#include <iomanip>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>
namespace RawrXD::NativeBridge {
namespace {
void field(std::string& out,const std::string& s){out+=std::to_string(s.size());out+=':';out+=s;}
bool readField(const std::string& s,size_t& pos,std::string& value){
 const auto colon=s.find(':',pos);
 if(colon==std::string::npos||colon==pos)return false;
 size_t n=0;
 auto [ptr,ec]=std::from_chars(s.data()+pos,s.data()+colon,n);
 if(ec!=std::errc{}||ptr!=s.data()+colon||n>s.size()-colon-1)return false;
 value=s.substr(colon+1,n);pos=colon+1+n;return true;
}
}
std::string canonicalTask(const Task& t){
 std::string out;field(out,t.id);field(out,t.tool);field(out,std::to_string(t.args.size()));
 for(const auto& a:t.args)field(out,a);
 field(out,std::to_string(t.dependencies.size()));
 for(const auto& d:t.dependencies)field(out,d);
 return out;
}
std::string taskFingerprint(const Task& t){return fnv1a64(canonicalTask(t));}
Result validateTaskIds(const std::vector<Task>& tasks){
 std::set<std::string> ids;
 for(const auto& t:tasks){
  if(t.id.empty()||t.id.size()>256||t.tool.empty()||t.tool.size()>256)return {false,{},"invalid id or tool"};
  if(!ids.insert(t.id).second)return {false,{},"duplicate task id: "+t.id};
 }
 return {true,"valid",{}};
}
Result validateTaskArguments(const Task& t,size_t maxArgs,size_t maxBytes){
 if(t.args.size()>maxArgs)return {false,{},"too many arguments"};
 size_t total=0;
 for(const auto& a:t.args){if(a.size()>maxBytes-total)return {false,{},"argument budget exceeded"};total+=a.size();}
 return {true,"valid",{}};
}
std::vector<std::string> dependencyClosure(const std::vector<Task>& tasks,const std::string& id,std::string& error){
 auto v=DependencyGraph::validate(tasks);if(!v.ok){error=v.error;return {};}
 std::map<std::string,const Task*> byId;for(const auto& t:tasks)byId[t.id]=&t;
 if(!byId.count(id)){error="unknown task";return {};}
 std::set<std::string> visited;std::vector<std::string> out;
 std::function<void(const std::string&)> walk=[&](const std::string& name){
  for(const auto& dep:byId.at(name)->dependencies)if(visited.insert(dep).second){walk(dep);out.push_back(dep);}
 };
 walk(id);return out;
}
std::vector<std::vector<std::string>> executionWaves(const std::vector<Task>& tasks,std::string& error){
 auto v=DependencyGraph::validate(tasks);if(!v.ok){error=v.error;return {};}
 std::set<std::string> done;std::vector<std::vector<std::string>> waves;
 while(done.size()<tasks.size()){
  std::vector<std::string> wave;
  for(const auto& t:tasks){
   if(done.count(t.id))continue;
   if(std::all_of(t.dependencies.begin(),t.dependencies.end(),[&](const auto& d){return done.count(d)!=0;}))wave.push_back(t.id);
  }
  if(wave.empty()){error="no runnable tasks";return {};}
  std::sort(wave.begin(),wave.end());for(const auto& id:wave)done.insert(id);
  waves.push_back(std::move(wave));
 }
 return waves;
}
std::string serializeReceipt(const ExecutionReceipt& r){
 std::string out="R1";field(out,r.taskId);field(out,r.tool);field(out,r.inputHash);field(out,r.outputHash);
 field(out,r.error);field(out,r.success?"1":"0");return out;
}
std::optional<ExecutionReceipt> parseReceipt(const std::string& s){
 if(s.substr(0,2)!="R1")return std::nullopt;
 size_t p=2;ExecutionReceipt r;std::string flag;
 if(!readField(s,p,r.taskId)||!readField(s,p,r.tool)||!readField(s,p,r.inputHash)||
    !readField(s,p,r.outputHash)||!readField(s,p,r.error)||!readField(s,p,flag)||p!=s.size()||
    (flag!="0"&&flag!="1"))return std::nullopt;
 r.success=flag=="1";return r;
}
ReceiptStore::ReceiptStore(std::filesystem::path p):journal_(std::move(p)){}
bool ReceiptStore::append(const ExecutionReceipt& r,std::string& error){return journal_.append(serializeReceipt(r),error);}
std::vector<ExecutionReceipt> ReceiptStore::read(std::string& error) const{
 auto lines=journal_.read(error);std::vector<ExecutionReceipt> out;
 if(!error.empty())return {};
 for(const auto& line:lines){auto r=parseReceipt(line);if(!r){error="invalid receipt";return {};}out.push_back(std::move(*r));}
 return out;
}
Result verifyReceiptChain(const std::vector<ExecutionReceipt>& receipts){
 std::set<std::string> ids;
 for(const auto& r:receipts){
  if(r.taskId.empty()||r.tool.empty()||r.inputHash.size()!=16||r.outputHash.size()!=16||
     !ids.insert(r.taskId).second)return {false,{},"invalid or duplicate receipt"};
  if(!std::all_of(r.inputHash.begin(),r.inputHash.end(),[](char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');})||
     !std::all_of(r.outputHash.begin(),r.outputHash.end(),[](char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');}))return {false,{},"invalid hash format"};
 }
 return {true,"receipt structure valid",{}};
}
Result runChecked(const Task& task,const ControlledTools& tools,const std::atomic<bool>& cancel,ExecutionReceipt& receipt){
 receipt={task.id,task.tool,taskFingerprint(task),{}, {},false};
 auto v=validateTaskArguments(task,128,1024*1024);
 Result r=v.ok?tools.invoke(task.tool,task.args,cancel):v;
 receipt.outputHash=fnv1a64(r.output);receipt.error=r.error;receipt.success=r.ok;
 return r;
}
Result runWave(const std::vector<Task>& tasks,const ControlledTools& tools,const std::atomic<bool>& cancel,
               std::vector<ExecutionReceipt>& receipts){
 auto v=DependencyGraph::validate(tasks);if(!v.ok)return v;
 std::string error;auto waves=executionWaves(tasks,error);if(!error.empty())return {false,{},error};
 std::map<std::string,const Task*> byId;for(const auto& t:tasks)byId[t.id]=&t;
 std::set<std::string> successful;bool allOk=true;
 for(const auto& wave:waves){
  for(const auto& id:wave){
   const Task& t=*byId.at(id);
   if(cancel.load())return {false,{},"cancelled"};
   if(!std::all_of(t.dependencies.begin(),t.dependencies.end(),[&](const auto& d){return successful.count(d)!=0;})){
    ExecutionReceipt skipped{t.id,t.tool,taskFingerprint(t),fnv1a64(""),"dependency failed",false};
    receipts.push_back(std::move(skipped));allOk=false;continue;
   }
   ExecutionReceipt rec;auto r=runChecked(t,tools,cancel,rec);
   if(r.ok)successful.insert(id);else allOk=false;
   receipts.push_back(std::move(rec));
  }
 }
 return {allOk,allOk?"all tasks succeeded":"one or more tasks failed",allOk?"":"task failure"};
}
Result validateOutput(const Result& r,size_t maxOutputBytes){
 if(!r.ok)return {false,{},r.error.empty()?"tool failed":r.error};
 if(r.output.size()>maxOutputBytes)return {false,{},"output limit exceeded"};
 return {true,r.output,{}};
}
Result checkExpectedText(const Result& r,const std::string& expected){
 if(!r.ok)return {false,{},r.error};
 return r.output==expected?Result{true,"match",{}}:Result{false,{},"unexpected output"};
}
BatchReport summarize(const std::vector<ExecutionReceipt>& receipts,size_t plannedTasks){
 BatchReport report;
 for(const auto& r:receipts){
  if(r.error=="dependency failed")++report.skipped;
  else if(r.success)++report.succeeded;
  else ++report.failed;
 }
 report.complete=receipts.size()==plannedTasks;
 return report;
}
}
