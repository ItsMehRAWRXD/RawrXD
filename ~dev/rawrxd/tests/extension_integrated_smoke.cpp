// Integrated smoke of production extension policies and command registry.
// The fixture does not execute JavaScript or install VSIX packages.
#include "../src/core/extension_manifest_policy.hpp"
#include "../src/core/extension_entry_policy.hpp"
#include "../src/core/extension_host_production.cpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
namespace fs = std::filesystem;
int main(){
 using namespace rawrxd::extensions;
 auto &host=RawrXD::Extensions::ExtensionHost::GetInstance();
 int total=0,fail=0;
 auto gate=[&](const char* n,bool ok){++total; if(!ok)++fail; std::cout<<(ok?"PASS ":"FAIL ")<<n<<'\n';};
 const auto root=fs::temp_directory_path()/"rawrxd-integration-fixture-20261106";
 std::error_code ec; fs::remove_all(root,ec); fs::create_directories(root/"publisher"/"dist",ec);
 if(ec){std::cerr<<ec.message();return 2;}
 std::ofstream(root/"publisher"/"dist"/"main.js")<<"exports.activate = () => {};";
 const std::string owner="publisher.demo", command="demo.echo";
 gate("manifest-identity",validManifestIdentity("publisher","demo","1.0.0"));
 gate("entry-policy",validRelativeMain("dist/main.js"));
 gate("entry-contained",entryWithinRoot(fs::absolute(root/"publisher"),fs::absolute(root/"publisher"/"dist"/"main.js")));
 gate("entry-file-exists",fs::is_regular_file(root/"publisher"/"dist"/"main.js"));
 host.Shutdown();gate("initialize",host.Initialize());
 int invoked=0;
 gate("register-extension-command",host.RegisterExtensionCommand(owner,command,[&](const std::string& input){++invoked;return input=="fixture";}));
 gate("command-dispatch",host.ExecuteCommand(command,"fixture")&&invoked==1);
 gate("command-failure-propagation",!host.ExecuteCommand(command,"bad")&&invoked==2);
 gate("duplicate-command-rejected",!host.RegisterExtensionCommand("other",command,[](const std::string&){return true;}));
 host.UnregisterExtensionCommands(owner);
 gate("unload-removes-command",!host.ExecuteCommand(command,"fixture")&&invoked==2);
 gate("reload-command",host.RegisterExtensionCommand(owner,command,[](const std::string&){return true;})&&host.ExecuteCommand(command,""));
 host.Shutdown();gate("shutdown-clears-command",!host.ExecuteCommand(command,""));
 gate("malicious-entry-rejected",!validRelativeMain("../outside.js"));
 gate("outside-entry-rejected",!entryWithinRoot(fs::absolute(root/"publisher"),fs::absolute(root/"outside.js")));
 fs::remove_all(root,ec);
 std::cout<<"RESULT "<<total-fail<<"/"<<total<<" passed\n";
 return fail?1:0;
}
