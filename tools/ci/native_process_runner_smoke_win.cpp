#include "native_process_runner_win.hpp"
#include <iostream>
#include <filesystem>
#include <fstream>
using rawrxd::build::runProcess;
int wmain(int argc, wchar_t** argv) {
 if(argc>1 && std::wstring(argv[1])==L"--streams") {
  for(int i=0;i<4000;++i) { std::cout<<"stdout "<<i<<" abcdefghijklmnopqrstuvwxyz\n"; std::cerr<<"stderr "<<i<<" abcdefghijklmnopqrstuvwxyz\n"; }
  return 17;
 }
 if(argc>1 && std::wstring(argv[1])==L"--hang") { Sleep(30000); return 0; }
 int failed=0;
 auto check=[&](bool pass,const char* label){ std::cout<<(pass?"PASS ":"FAIL ")<<label<<"\n"; if(!pass)++failed; };
 wchar_t self[MAX_PATH]{}; GetModuleFileNameW(nullptr,self,MAX_PATH);
 auto p=runProcess(self,{L"--streams"},20000);
 check(p.launched&&!p.timedOut&&p.exitCode==17,"exit code");
 check(p.stdoutText.find("stdout 3999")!=std::string::npos,"concurrent stdout");
 check(p.stderrText.find("stderr 3999")!=std::string::npos,"concurrent stderr");
 auto t=runProcess(self,{L"--hang"},250);
 check(t.launched&&t.timedOut,"enforced timeout");
 auto bad=runProcess(L"Z:\\rawrxd-does-not-exist.exe",{},1000);
 check(!bad.launched&&!bad.error.empty(),"launch error");
 namespace fs=std::filesystem;
 wchar_t temp[MAX_PATH]{}; GetTempPathW(MAX_PATH,temp);
 fs::path dir=fs::path(temp)/("rawrxd-build-"+std::to_string(GetCurrentProcessId()));
 fs::create_directories(dir);
 auto src=dir/"hello.c",obj=dir/"hello.obj",exe=dir/"hello.exe";
 {std::ofstream f(src); f<<"#include <stdio.h>\nint main(void){puts(\"RAWRXD_OK\");return 0;}\n";}
 auto c=runProcess(L"cl.exe",{L"/nologo",L"/c",src.wstring(),L"/Fo"+obj.wstring()},60000,dir.wstring());
 check(c.launched&&!c.timedOut&&c.exitCode==0&&fs::exists(obj),"C compile to object");
 if(fs::exists(obj)) {
  auto l=runProcess(L"link.exe",{L"/nologo",obj.wstring(),L"/OUT:"+exe.wstring()},60000,dir.wstring());
  check(l.launched&&!l.timedOut&&l.exitCode==0&&fs::exists(exe),"object link");
 } else check(false,"object link");
 if(fs::exists(exe)) {
  auto e=runProcess(exe.wstring(),{},10000,dir.wstring());
  check(e.launched&&!e.timedOut&&e.exitCode==0&&e.stdoutText.find("RAWRXD_OK")!=std::string::npos,"execute binary");
 } else check(false,"execute binary");
 // Multi-unit C++ build validates symbol resolution and the C++ runtime.
 auto helper=dir/"helper.cpp",maincpp=dir/"main.cpp";
 auto helperObj=dir/"helper.obj",mainObj=dir/"main.obj",cppExe=dir/"multi.exe";
 {std::ofstream f(helper);f<<"extern \"C\" int answer(){return 42;}\\n";}
 {std::ofstream f(maincpp);f<<"#include <iostream>\\nextern \"C\" int answer();\\nint main(){std::cout<<answer()<<\"\\\\n\";return answer()==42?0:1;}\\n";}
 auto hc=runProcess(L"cl.exe",{L"/nologo",L"/EHsc",L"/std:c++17",L"/c",helper.wstring(),L"/Fo"+helperObj.wstring()},60000,dir.wstring());
 auto mc=runProcess(L"cl.exe",{L"/nologo",L"/EHsc",L"/std:c++17",L"/c",maincpp.wstring(),L"/Fo"+mainObj.wstring()},60000,dir.wstring());
 check(hc.launched&&hc.exitCode==0&&mc.launched&&mc.exitCode==0&&fs::exists(helperObj)&&fs::exists(mainObj),"multi-unit C++ object compilation");
 if(fs::exists(helperObj)&&fs::exists(mainObj)) {
  auto lk=runProcess(L"link.exe",{L"/nologo",helperObj.wstring(),mainObj.wstring(),L"/OUT:"+cppExe.wstring()},60000,dir.wstring());
  check(lk.launched&&!lk.timedOut&&lk.exitCode==0&&fs::exists(cppExe),"multi-unit C++ linking");
 } else check(false,"multi-unit C++ linking");
 if(fs::exists(cppExe)) {
  auto e=runProcess(cppExe.wstring(),{},10000,dir.wstring());
  check(e.launched&&!e.timedOut&&e.exitCode==0&&e.stdoutText.find("42")!=std::string::npos,"multi-unit C++ executable");
 } else check(false,"multi-unit C++ executable");
 std::error_code ec;fs::remove_all(dir,ec);
 std::cout<<"RESULT "<<(failed?"FAIL":"PASS")<<" failures="<<failed<<"\n";
 return failed?1:0;
}
