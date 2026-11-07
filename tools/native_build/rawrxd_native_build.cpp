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
#else
#include <sys/wait.h>
#include <unistd.h>
#endif
namespace fs = std::filesystem;
static int run(const std::vector<std::string>& args) {
    if(args.empty()) return 2;
#ifdef _WIN32
    auto quote=[](const std::string& s) {
        std::string o="\"";unsigned slashes=0;
        for(char c:s) {
            if(c=='\\'){++slashes;continue;}
            if(c=='"'){o.append(slashes*2+1,'\\');o+='"';slashes=0;continue;}
            o.append(slashes,'\\');slashes=0;o+=c;
        }
        o.append(slashes*2,'\\');return o+"\"";
    };
    std::string cmd;
    for(const auto& a:args){if(!cmd.empty())cmd+=' ';cmd+=quote(a);}
    int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,cmd.data(),(int)cmd.size(),nullptr,0);
    if(n<=0)return 2;
    std::wstring wide(n,L'\0');
    if(MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,cmd.data(),(int)cmd.size(),wide.data(),n)!=n)return 2;
    wide.push_back(L'\0');
    STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};
    if(!CreateProcessW(nullptr,wide.data(),nullptr,nullptr,FALSE,0,nullptr,nullptr,&si,&pi))return 127;
    WaitForSingleObject(pi.hProcess,INFINITE);DWORD exitCode=127;
    GetExitCodeProcess(pi.hProcess,&exitCode);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);
    return static_cast<int>(exitCode);
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
    if(compiler.empty()||source.empty()||output.empty()||(mode!="build"&&mode!="run"))return 2;
    std::error_code ec;
    if(!fs::is_regular_file(fs::u8path(source),ec)){std::cerr<<"source file missing\\n";return 3;}
    std::vector<std::string> args{compiler};
    for(int i=5;i<argc;++i)args.emplace_back(argv[i]);
    const auto compilerName=fs::path(compiler).filename().string();
    const bool msvc=(compilerName=="cl"||compilerName=="cl.exe"||compilerName=="CL.EXE");
    if(msvc) {
        args.push_back("/nologo");args.push_back("/EHsc");args.push_back("/std:c++17");
        args.push_back(source);args.push_back("/Fe:"+output);
    } else {
        args.push_back(source);args.push_back("-o");args.push_back(output);
    }
    const int compileResult=run(args);
    if(compileResult!=0)return compileResult;
    if(!fs::is_regular_file(fs::u8path(output),ec)){std::cerr<<"compiler returned success without output\\n";return 4;}
    if(mode=="run")return run({fs::absolute(fs::u8path(output)).u8string()});
    return 0;
}
