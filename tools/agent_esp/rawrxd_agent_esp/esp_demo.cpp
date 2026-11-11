#include "esp_runtime.hpp"
#include "esp_cli.hpp"
#include <chrono>
#include <iostream>
#include <thread>
int main(int argc,char**argv){
 std::string path=argc>1?argv[1]:"agentic_live.jsonl";
 rawrxd::esp::Bus bus(8192);rawrxd::esp::ConsoleView view;
 rawrxd::esp::Recorder rec(bus,path,[&](const rawrxd::esp::Event& e){view(e);});
 if(!rec.start()){std::cerr<<"Failed to open "<<path<<"\n";return 2;}
 rawrxd::esp::RuntimeESP esp(bus,1);
 esp.model_load("demo.gguf");esp.tokenizer(true);esp.prefill_start(100,101);
 std::this_thread::sleep_for(std::chrono::milliseconds(30));esp.prefill_end();esp.decode_start();
 for(int i=0;i<15;i++){esp.token(1000+i,"token");std::this_thread::sleep_for(std::chrono::milliseconds(30));if(i%5==0)esp.tick();}
 esp.snap("tool_ready");esp.tool_start("read test.cpp");esp.tool_result("read completed",0);
 esp.build_start("cl test.cpp");esp.build_result(0);esp.test_start("test.exe");esp.test_result(0);esp.finish(true);
 rec.stop();std::cout<<"ESP_DEMO_PASS dropped="<<bus.dropped()<<"\n";
}
