#include "../src/reverse_engineering/RawrCompiler.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
namespace fs=std::filesystem;
int main(){
 using RawrXD::ReverseEngineering::RawrCompiler;
 const auto dir=fs::temp_directory_path()/"rawrxd-compiler-acceptance";
 fs::create_directories(dir);
 int total=0,failed=0;
 auto check=[&](const char* label,bool ok){++total;failed+=!ok;std::cout<<(ok?"PASS ":"FAIL ")<<label<<'\n';};
 auto run=[&](const char* ext,const char* body,const char* tag){
  const auto source=dir/(std::string(tag)+ext);
  {std::ofstream out(source);out<<body;}
  RawrCompiler compiler;
  auto compiled=compiler.CompileSource(source.string());
  check((std::string(tag)+"-compile").c_str(),compiled.success && fs::exists(compiled.objectFile));
  if(!compiled.success){for(auto& e:compiled.errors)std::cerr<<e<<'\n';return;}
  const auto exe=dir/(std::string(tag)+".exe");
  check((std::string(tag)+"-link").c_str(),compiler.Link({compiled.objectFile},exe.string()) && fs::exists(exe));
 };
 run(".c","int main(void){return 0;}","c17");
 run(".cpp","int main(){return 0;}","cpp17");
 std::cout<<"RESULT "<<total-failed<<"/"<<total<<" passed\n";
 return failed?1:0;
}
