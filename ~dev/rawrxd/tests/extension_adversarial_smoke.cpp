// Adversarial acceptance of the production extension registry and path policy.
#include "../src/core/extension_entry_policy.hpp"
#include "../src/core/extension_host_production.cpp"
#include <atomic>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
namespace fs=std::filesystem;
int main(){
 auto& host=RawrXD::Extensions::ExtensionHost::GetInstance();
 int total=0,fail=0;
 auto check=[&](const char* name,bool pass){++total;fail+=!pass;std::cout<<(pass?"PASS ":"FAIL ")<<name<<'\n';};
 host.Shutdown();host.Initialize();
 check("unknown-command-fails-closed",!host.ExecuteCommand("not-registered",""));
 check("oversize-command-rejected",!host.RegisterCommand(std::string(257,'x'),[](auto const&){return true;}));
 check("embedded-null-command-rejected",!host.RegisterCommand(std::string("abc\0def",7),[](auto const&){return true;}));
 check("owner-tab-rejected",!host.RegisterExtensionCommand("bad\towner","tab",[](auto const&){return true;}));
 check("owner-del-rejected",!host.RegisterExtensionCommand(std::string("bad")+char(127),"del",[](auto const&){return true;}));
 std::atomic<int> calls{0};
 check("register-threadsafe-handler",host.RegisterExtensionCommand("owner","counter",[&](auto const&){++calls;return true;}));
 std::vector<std::thread> workers;
 for(int i=0;i<8;++i)workers.emplace_back([&]{for(int j=0;j<1000;++j)host.ExecuteCommand("counter","");});
 for(auto& t:workers)t.join();
 check("parallel-dispatch-8000",calls==8000);
 host.UnregisterExtensionCommands("wrong-owner");
 check("wrong-owner-does-not-unload",host.ExecuteCommand("counter","")&&calls==8001);
 host.UnregisterExtensionCommands("owner");
 check("correct-owner-unloads",!host.ExecuteCommand("counter",""));
 auto root=fs::temp_directory_path()/"rawrxd-adversarial-policy-20261106";
 std::error_code ec;fs::remove_all(root,ec);fs::create_directories(root/"installed",ec);fs::create_directories(root/"outside",ec);
 if(ec){std::cerr<<"fixture setup error: "<<ec.message()<<'\n';return 2;}
 std::ofstream(root/"outside"/"main.js")<<"dummy";
 fs::create_directory_symlink(root/"outside",root/"installed"/"link",ec);
 if(!ec)check("symlink-escape-rejected",!rawrxd::extensions::entryWithinRoot(fs::absolute(root/"installed"),fs::absolute(root/"installed"/"link"/"main.js")));
 else std::cout<<"SKIP symlink-escape-rejected (symlink creation unavailable: "<<ec.message()<<")\n";
 fs::remove_all(root,ec);host.Shutdown();
 std::cout<<"RESULT "<<total-fail<<"/"<<total<<" passed\n";
 return fail?1:0;
}
