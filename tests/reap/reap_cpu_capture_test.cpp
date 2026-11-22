#include "ReapCpuCapture.hpp"
#include <iostream>
#include <chrono>
#include <iterator>
using namespace reap_capture;
int main(int argc, char** argv) {
    if(argc != 2) return 2;
    const std::filesystem::path parent=argv[1];
    std::filesystem::create_directories(parent);
    const auto stamp=std::chrono::steady_clock::now().time_since_epoch().count();
    std::filesystem::path base;
    for (unsigned i=0; i<100; ++i) {
        base=parent/("capture-"+std::to_string(stamp)+"-"+std::to_string(i));
        if (std::filesystem::create_directory(base)) break;
        base.clear();
    }
    if (base.empty()) return 2;
    int fail=0, pass=0;
    auto check=[&](bool ok,const char* label){std::cout<<(ok?"PASS ":"FAIL ")<<label<<'\n';ok?++pass:++fail;};
    auto rejects=[&](const char* label,auto fn){try{fn();check(false,label);}catch(const std::exception&){check(true,label);}};
    check(ParseTokens("1, 2\t0\r\n")==std::vector<uint32_t>{1,2,0},"token parsing");
    rejects("invalid token suffix",[]{ParseTokens("1 2x");});
    rejects("negative token",[]{ParseTokens("-1");});
    rejects("overflow",[]{ParseTokens("4294967296");});
    rejects("empty",[]{ParseTokens(" , ");});
    rejects("vocab rejection",[&]{Capture c(base/"bad",{0,3},3);});
    rejects("short token sequence",[&]{Capture c(base/"short",{0},3);});
    Capture c(base/"full",{1,2,0},3);
    rejects("existing directory",[&]{Capture d(base/"full",{1,2,0},3);});
    rejects("wrong shape",[&]{c.Append({1,2});});
    rejects("nonfinite",[&]{c.Append({1,2,std::numeric_limits<float>::infinity()});});
    c.Append({1,2,3});
    rejects("incomplete manifest",[&]{c.Finish();});
    check(!std::filesystem::exists(base/"full"/"manifest.tsv"),"no manifest on incomplete capture");
    c.Append({3,2,1});c.Finish();
    std::ifstream m(base/"full"/"manifest.tsv"); std::string s((std::istreambuf_iterator<char>(m)),{}); m.close();
    check(s=="s\t0\t1\t2\tcpu_logits_pos0.bin\ns\t1\t2\t0\tcpu_logits_pos1.bin\n","exact aligned manifest");
    check(std::filesystem::file_size(base/"full"/"cpu_logits_pos0.bin")==12 && c.Count()==2,"binary length and count");
    rejects("duplicate finish",[&]{c.Finish();});
    rejects("append after finish",[&]{c.Append({1,2,3});});
    std::cout<<pass<<" passed, "<<fail<<" failed\n";
    if (!fail) std::filesystem::remove_all(base);
    return fail?1:0;
}
