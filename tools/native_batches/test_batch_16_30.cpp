#include "native_agent_batch_16_30.hpp"
#include <atomic>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
using namespace RawrXD::NativeBridge;
static void req(bool b,const char* msg){if(!b)throw std::runtime_error(msg);}
int main(){
 namespace fs=std::filesystem;
 auto root=fs::temp_directory_path()/"rawrxd_batch_16_30_test";
 fs::remove_all(root);fs::create_directories(root/"sub");
 try {
 {std::ofstream f(root/"sub"/"a.txt",std::ios::binary);f<<"alpha\nbeta\n";}
 req(readBounded(root,"sub/a.txt",100).output=="alpha\nbeta\n","16 read");
 req(!readBounded(root,"sub/a.txt",3).ok,"16 size limit");
 req(listDirectory(root,"sub",10).output=="a.txt\n","17 list");
 req(replaceExact(root,"sub/a.txt","beta","gamma").ok,"18 replace");
 req(readBounded(root,"sub/a.txt",100).output=="alpha\ngamma\n","18 verify");
 req(insertLine(root,"sub/a.txt",2,"middle").ok,"19 insert");
 req(eraseLine(root,"sub/a.txt",1).ok,"20 erase");
 req(readBounded(root,"sub/a.txt",100).output=="middle\ngamma\n","20 verify");
 req(diffLines("a\nb\n","a\nc\n",10).output=="-b\n+c\n","21 diff");
 req(fnv1a64("hello")=="a430d84680aabd0b","22 FNV");
 req(fileFingerprint(root,"sub/a.txt",100).ok,"23 fingerprint");
 auto stat=statFile(root,"sub/a.txt");req(stat && stat->bytes==13,"24 stat");
 req(scanWorkspace(root,".txt",10).output=="sub/a.txt\n","25 scan");
 TaskTracker tracker;
 std::vector<Task> tasks={{"a","echo",{},{}},{"b","echo",{},{"a"}},{"c","echo",{},{"b"}}};
 req(tracker.load(tasks).ok,"26 tracker load");
 req(tracker.ready().size()==1&&tracker.ready()[0].id=="a","27 ready");
 req(!tracker.start("b")&&tracker.start("a"),"28 start");
 req(tracker.finish("a",false)&&tracker.complete(),"29 failure propagation");
 auto states=tracker.statuses();
 req(states["b"]==ScheduleItem::Status::Skipped&&states["c"]==ScheduleItem::Status::Skipped,"29 skip");
 req(!validateWorkspacePath(root,"../outside").ok,"30 confinement");
 ToolRegistry reg;req(registerWorkspaceTools(reg,root).ok,"30 registry");
 std::atomic<bool> cancel{false};
 req(reg.execute("workspace.read",{"sub/a.txt"},cancel).ok,"30 actual tool");
 req(!reg.execute("workspace.read",{"../outside"},cancel).ok,"30 tool confinement");
 fs::remove_all(root);
 std::cout<<"BATCH_16_30_PASS\n";return 0;
 }catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<'\n';fs::remove_all(root);return 1;}
}
