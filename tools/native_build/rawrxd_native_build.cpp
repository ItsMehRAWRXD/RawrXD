// Portable, local-only compiler/build/link driver for native IDE tool invocation.
// Uses explicit argv and filesystem APIs; never invokes a shell.
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <cerrno>
#ifdef _WIN32
#include <windows.h>
#include "windows_process_runner.hpp"
#else
#include <sys/wait.h>
#include <unistd.h>
#endif
namespace fs = std::filesystem;
static int run(const std::vector<std::string>& args) {
    if(args.empty()) return 2;
#ifdef _WIN32
    return rawrxd::build::execute(args).code;
#else
    std::vector<char*> argv;
    for(const auto& a:args)argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);
    pid_t pid=fork();if(pid<0)return 127;
    if(pid==0){execvp(argv[0],argv.data());_exit(errno==ENOENT?127:126);}
    int status=0;while(waitpid(pid,&status,0)<0){if(errno!=EINTR)return 127;}
    return WIFEXITED(status)?WEXITSTATUS(status):128+(WIFSIGNALED(status)?WTERMSIG(status):0);
#endif
}
int main(int argc,char** argv) {
    if(argc<5){std::cerr<<"usage: rawrxd-native-build <compiler> <source.cpp> <output> <build|run> [compiler flags...]\\n";return 2;}
    const std::string compiler=argv[1],source=argv[2],output=argv[3],mode=argv[4];
    if(compiler.empty()||source.empty()||output.empty()||(mode!="build"&&mode!="run"&&mode!="object"&&mode!="link"))return 2;
    std::error_code ec;
    if(!fs::is_regular_file(fs::u8path(source),ec)){std::cerr<<"source file missing\\n";return 3;}
    std::vector<std::string> args{compiler};
    for(int i=5;i<argc;++i)args.emplace_back(argv[i]);
    const auto compilerName=fs::path(compiler).filename().string();
    const bool msvc=(compilerName=="cl"||compilerName=="cl.exe"||compilerName=="CL.EXE");
    if(msvc) {
        args.push_back("/nologo");
        if(mode=="object") {
            args.push_back("/c");args.push_back(source);args.push_back("/Fo:"+output);
        } else {
            if(mode!="link") {args.push_back("/EHsc");args.push_back("/std:c++17");}
            args.push_back(source);args.push_back("/Fe:"+output);
        }
    } else {
        if(mode=="object")args.push_back("-c");
        args.push_back(source);args.push_back("-o");args.push_back(output);
    }
    // Never accept a stale executable from a previous successful build.
    // Refuse to delete a source file accidentally supplied as the output.
    if(fs::absolute(fs::u8path(source),ec)==fs::absolute(fs::u8path(output),ec)) return 2;
    ec.clear();
    fs::remove(fs::u8path(output),ec);
    if(ec) {std::cerr<<"cannot clear prior build output\\n";return 4;}
    const int compileResult=run(args);
    if(compileResult!=0)return compileResult;
    if(!fs::is_regular_file(fs::u8path(output),ec)){std::cerr<<"compiler returned success without output\\n";return 4;}
    if(mode=="run")return run({fs::absolute(fs::u8path(output)).u8string()});
    return 0;
}
