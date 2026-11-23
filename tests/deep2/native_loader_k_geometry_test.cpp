#include "../../~dev/rawrxd/src/deep2/GGUFLoader.hpp"
#include <cassert>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
static void put32(std::ostream& o,uint32_t v){for(int i=0;i<4;++i)o.put(char(v>>(8*i)));}
static void put64(std::ostream& o,uint64_t v){for(int i=0;i<8;++i)o.put(char(v>>(8*i)));}
static void putString(std::ostream& o,const std::string& s){put64(o,s.size());o.write(s.data(),std::streamsize(s.size()));}
int main(){
    struct Expected{uint32_t type;size_t bytes;};
    const Expected expected[]={{10,84},{11,110},{12,144},{13,176},{14,210},{15,292}};
    for(const auto& e:expected){
        const auto path=std::filesystem::temp_directory_path()/("rawrxd-k-loader-"+std::to_string(e.type)+".gguf");
        {
            std::ofstream out(path,std::ios::binary|std::ios::trunc);assert(out);
            out.write("GGUF",4);put32(out,3);put64(out,1);put64(out,0);
            putString(out,"tensor");put32(out,1);put64(out,256);put32(out,e.type);put64(out,0);
            const auto header=static_cast<size_t>(out.tellp());
            for(size_t i=header;i%32;++i)out.put('\0');
            for(size_t i=0;i<e.bytes;++i)out.put('\0');
            assert(out.good());
        }
        Deep2::GGUFLoader loader;
        if(!loader.load(path.string())){std::cerr<<"loader rejected type "<<e.type<<": "<<loader.error()<<"\n";return 1;}
        const auto* tensor=loader.getTensor("tensor");
        assert(tensor&&static_cast<uint32_t>(tensor->type)==e.type&&tensor->sizeBytes==e.bytes);
        loader.close();std::filesystem::remove(path);
    }
    std::cout<<"Deep2 mapped GGUF loader accepts Q2_K through Q6_K tensor payloads\n";
}
