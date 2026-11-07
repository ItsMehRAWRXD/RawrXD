// Regression tests exercise the production command registry implementation.
#include "../src/core/extension_host_production.cpp"
#include <iostream>
#include <stdexcept>
#include <string>
static int total=0,fail=0;
static void check(const char* name,bool ok){++total;std::cout<<(ok?"PASS ":"FAIL ")<<name<<"\n";if(!ok)++fail;}
int main(){
 using RawrXD::Extensions::ExtensionHost;
 auto& host=ExtensionHost::GetInstance();
 host.Shutdown();
 check("closed-before-init",!host.ExecuteCommand("x",""));
 check("reject-before-init",!host.RegisterCommand("x",[](const std::string&){return true;}));
 check("initialize",host.Initialize()&&host.IsInitialized());
 check("reject-empty-command",!host.RegisterCommand("",[](const std::string&){return true;}));
 check("reject-control-character",!host.RegisterCommand("x\ny",[](const std::string&){return true;}));
 check("reject-empty-handler",!host.RegisterCommand("missing",{}));
 int calls=0;
 check("register-command",host.RegisterCommand("host.run",[&](const std::string& arg){++calls;return arg=="ok";}));
 check("reject-duplicate",!host.RegisterCommand("host.run",[](const std::string&){return true;}));
 check("execute-success",host.ExecuteCommand("host.run","ok")&&calls==1);
 check("execute-negative-result",!host.ExecuteCommand("host.run","bad")&&calls==2);
 check("reject-unknown",!host.ExecuteCommand("unknown",""));
 check("reject-empty-owner",!host.RegisterExtensionCommand("","ext.run",[](const std::string&){return true;}));
 check("reject-whitespace-owner",!host.RegisterExtensionCommand("bad owner","ext.run",[](const std::string&){return true;}));
 check("reject-control-owner",!host.RegisterExtensionCommand(std::string("bad")+char(1)+"owner","ext.run",[](const std::string&){return true;}));
 check("reject-long-owner",!host.RegisterExtensionCommand(std::string(257, 'x'),"ext.run",[](const std::string&){return true;}));
 check("reject-path-owner",!host.RegisterExtensionCommand("bad/owner","ext.run",[](const std::string&){return true;}));
 check("reject-windows-path-owner",!host.RegisterExtensionCommand("bad\\\\owner","ext.run",[](const std::string&){return true;}));
 check("register-owned",host.RegisterExtensionCommand("ext","ext.run",[](const std::string&){return true;}));
 check("reject-owner-duplicate",!host.RegisterExtensionCommand("other","ext.run",[](const std::string&){return true;}));
 check("execute-owned",host.ExecuteCommand("ext.run",""));
 host.UnregisterExtensionCommands("ext");
 check("unload-removes-command",!host.ExecuteCommand("ext.run",""));
 check("unload-preserves-host-command",host.ExecuteCommand("host.run","ok"));
 check("exception-fails-closed",host.RegisterCommand("throws",[](const std::string&)->bool{throw std::runtime_error("test");})&&!host.ExecuteCommand("throws",""));
 check("nested-dispatch",host.RegisterCommand("nested",[&](const std::string&){return host.ExecuteCommand("host.run","ok");})&&host.ExecuteCommand("nested",""));
 check("unregister-command",host.UnregisterCommand("nested")&&!host.ExecuteCommand("nested",""));
 host.Shutdown();
 check("shutdown-closes",!host.IsInitialized()&&!host.ExecuteCommand("host.run","ok"));
 check("restart-empty",host.Initialize()&&!host.ExecuteCommand("host.run","ok"));
 host.Shutdown();
 std::cout<<"RESULT "<<total-fail<<"/"<<total<<" passed\n";
 return fail?1:0;
}
