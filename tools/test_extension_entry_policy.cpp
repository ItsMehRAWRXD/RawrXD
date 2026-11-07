// Tests production extension_entry_policy.hpp, not QuickJS or VSIX activation.
#include "../~dev/rawrxd/src/core/extension_entry_policy.hpp"
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
namespace fs=std::filesystem;
int main() {
    const auto root=fs::temp_directory_path()/"rawrxd_extension_policy_smoke";
    std::error_code ec;
    fs::remove_all(root,ec);
    fs::create_directories(root/"installed"/"out",ec);
    fs::create_directories(root/"other",ec);
    if(ec) { std::cerr<<ec.message()<<"\n";return 2; }
    std::ofstream(root/"installed"/"out"/"main.js")<<"module.exports={};\n";
    std::ofstream(root/"other"/"outside.js")<<"outside\n";
    const auto base=root/"installed";
    struct Case {const char*name;fs::path path;bool allowed;};
    const std::array<Case,13> cases = {{
      {"valid_nested",base/"out"/"main.js",true},
      {"valid_nonexistent_leaf",base/"out"/"future.js",true},
      {"valid_relative_dot",base/"out"/"."/"main.js",true},
      {"valid_parent_inside",base/"out"/".."/"out"/"main.js",true},
      {"reject_parent_traversal",base/".."/"other"/"outside.js",false},
      {"reject_sibling",root/"other"/"outside.js",false},
      {"reject_prefix_sibling",root/"installed_evil"/"main.js",false},
      {"reject_same_root",base,false},
      {"reject_empty",fs::path{},false},
      {"reject_absolute_outside",fs::temp_directory_path()/"outside.js",false},
      {"reject_deep_traversal",base/"out"/".."/".."/"other"/"outside.js",false},
      {"valid_nested_future",base/"out"/"future"/"main.js",true},
      {"reject_root_parent",root,false}
    }};
    int passed=0;
    for(const auto& c:cases) {
      bool got=rawrxd::extensions::entryWithinRoot(base,c.path);
      bool ok=got==c.allowed;
      passed+=ok;std::cout<<c.name<<"="<<(ok?"PASS":"FAIL")<<"\n";
    }
    fs::create_directory_symlink(root/"other",base/"linked_out",ec);
    if(!ec) {
      bool ok=!rawrxd::extensions::entryWithinRoot(base,base/"linked_out"/"outside.js");
      passed+=ok;std::cout<<"reject_symlink_escape="<<(ok?"PASS":"FAIL")<<"\n";
    } else {
      std::cout<<"reject_symlink_escape=SKIP ("<<ec.message()<<")\n";
    }
    bool emptyRoot=!rawrxd::extensions::entryWithinRoot({},base/"out"/"main.js");
    passed+=emptyRoot;std::cout<<"reject_empty_root="<<(emptyRoot?"PASS":"FAIL")<<"\n";
    const int expected=ec?14:15;
    fs::remove_all(root,ec);
    std::cout<<"EXTENSION_ENTRY_POLICY="<<passed<<"/"<<expected<<"\n";
    return passed==expected?0:1;
}
