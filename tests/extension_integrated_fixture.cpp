// Model-free integration fixture. Fail-closed bridge is NOT a JS runtime.
#include "../~dev/rawrxd/src/core/extension_entry_policy.hpp"
#include "../~dev/rawrxd/src/core/extension_manifest_policy.hpp"
#include "../~dev/rawrxd/src/core/extension_signature_policy.hpp"
#include "../~dev/rawrxd/src/core/extension_read_policy.hpp"
#include <algorithm>
#include <chrono>
#include <iterator>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
namespace fs=std::filesystem;
using namespace rawrxd::extensions;
extern "C" bool RawrXD_JSExt_Initialize();
extern "C" bool RawrXD_JSExt_IsInitialized();
extern "C" bool RawrXD_JSExt_LoadExtension(const char*);
extern "C" void RawrXD_JSExt_Shutdown();
int main(){
 int failures=0;auto check=[&](bool ok,const char* label){std::cout<<(ok?"PASS ":"FAIL ")<<label<<'\n';if(!ok)++failures;};
 auto root=fs::temp_directory_path()/("rawrxd_integrated_fixture_"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));std::error_code ec;fs::remove_all(root,ec);fs::create_directories(root/"extension",ec);if(ec){std::cerr<<"BLOCKED fixture creation\n";return 2;}
 const std::string payload="module.exports.activate = function() { return 42; };";
 check(validManifestIdentity("local","fixture","1.0.0"),"manifest identity");
 check(validRelativeMain("extension.js"),"manifest entry");
 check(entryWithinRoot(root,root/"extension"/"extension.js"),"entry containment");
 std::string serialized;
 check(writeExactly(payload.data(),payload.size(),[&](const char*p,size_t n){auto k=std::min<size_t>(3,n);serialized.append(p,k);return k;}),"partial-write transport");
 {std::ofstream out(root/"extension"/"extension.js",std::ios::binary);out.write(serialized.data(),static_cast<std::streamsize>(serialized.size()));check(out.good(),"fixture persisted");}
 std::ifstream in(root/"extension"/"extension.js",std::ios::binary);std::string persisted((std::istreambuf_iterator<char>(in)),{});
 std::string loaded(payload.size(),'\0');size_t pos=0;
 check(readExactly(loaded.data(),loaded.size(),[&](char*p,size_t n){auto k=pos<=persisted.size()?std::min<size_t>({n,4,persisted.size()-pos}):size_t{0};std::copy_n(persisted.data()+pos,k,p);pos+=k;return k;}),"partial-read transport");
 check(loaded==payload,"fixture round-trip integrity");
 check(!writeExactly(payload.data(),payload.size(),[](const char*,size_t){return size_t{0};}),"zero-progress write fails closed");
 check(!writeExactly(payload.data(),payload.size(),[](const char*,size_t n){return n+1;}),"oversized write fails closed");
 check(!readExactly(loaded.data(),loaded.size(),[](char*,size_t){return size_t{0};}),"premature EOF fails closed");
 check(!readExactly(loaded.data(),loaded.size(),[](char*,size_t n){return n+1;}),"oversized read fails closed");
 check(!mayInstallVSIX(false,""),"unsigned installation denied by default");
 check(mayInstallVSIX(false,"1"),"unsigned installation explicit opt-in");
 check(!validRelativeMain("../escape.js"),"traversal denied");
 check(!entryWithinRoot(root,root.parent_path()/"escape.js"),"outside-root denied");
 check(!RawrXD_JSExt_Initialize(),"no-runtime initialization fails closed");
 check(!RawrXD_JSExt_IsInitialized(),"no-runtime remains uninitialized");
 check(!RawrXD_JSExt_LoadExtension((root/"extension").string().c_str()),"no-runtime extension load fails closed");
 RawrXD_JSExt_Shutdown();check(!RawrXD_JSExt_IsInitialized(),"shutdown remains closed");
 fs::remove_all(root,ec);check(!ec,"fixture cleanup");
 std::cout<<"INTEGRATED_FIXTURE failures="<<failures<<'\n';return failures?1:0;
}
