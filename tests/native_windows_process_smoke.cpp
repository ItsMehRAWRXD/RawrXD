#include "../tools/native_build/windows_process_runner.hpp"
#ifdef _WIN32
#include <windows.h>
#include <iostream>
#include <string>
int main(int argc,char** argv){
    if(argc>1){
        if(std::string(argv[1])=="emit"){
            for(int i=0;i<1000;++i){std::cout<<"stdout "<<i<<"\n";std::cerr<<"stderr "<<i<<"\n";}
            return 23;
        }
        if(std::string(argv[1])=="sleep"){Sleep(5000);return 0;}
    }
    char path[MAX_PATH]{};
    if(!GetModuleFileNameA(nullptr,path,MAX_PATH))return 2;
    auto a=rawrxd::build::execute({path,"emit"},10000);
    if(!a.launched||a.timedOut||a.code!=23){std::cerr<<"FAIL concurrent drain / exit propagation\n";return 1;}
    auto b=rawrxd::build::execute({path,"sleep"},150);
    if(!b.launched||!b.timedOut||b.code!=124){std::cerr<<"FAIL enforced timeout\n";return 1;}
    std::cout<<"WINDOWS_PROCESS_GATE PASS\n";return 0;
}
#else
int main(){return 0;}
#endif
