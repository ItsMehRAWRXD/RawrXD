#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>

static bool readBytes(std::fstream& f, void* p, std::streamsize n) { return bool(f.read(static_cast<char*>(p), n)); }
static bool skip(std::fstream& f, std::uint64_t n) { f.seekg(static_cast<std::streamoff>(n), std::ios::cur); return bool(f); }
static bool str(std::fstream& f, std::string& s) { std::uint64_t n=0; if(!readBytes(f,&n,8)||n>1ull<<20)return false; s.resize(static_cast<size_t>(n)); return readBytes(f,s.data(),static_cast<std::streamsize>(n)); }
static bool value(std::fstream& f, std::uint32_t t) {
    switch(t){
    case 0: case 1: return skip(f,1); case 2: case 3: return skip(f,2);
    case 4: case 5: case 6: return skip(f,4); case 7: return skip(f,1); case 10: case 11: case 12: return skip(f,8);
    case 8: { std::string s; return str(f,s); }
    case 9: { std::uint32_t et=0; std::uint64_t n=0; if(!readBytes(f,&et,4)||!readBytes(f,&n,8))return false; for(std::uint64_t i=0;i<n;++i)if(!value(f,et))return false; return true; }
    default: return false;
    }
}
int main(int argc,char**argv){
    if(argc!=2){std::cerr<<"usage: gguf_split_metadata_patch <file>\n";return 2;}
    std::fstream f(argv[1],std::ios::in|std::ios::out|std::ios::binary); if(!f){std::cerr<<"OPEN_FAIL\n";return 3;}
    std::uint32_t magic=0,version=0; std::uint64_t tensors=0,keys=0;
    if(!readBytes(f,&magic,4)||!readBytes(f,&version,4)||!readBytes(f,&tensors,8)||!readBytes(f,&keys,8)||magic!=0x46554747u){std::cerr<<"HEADER_FAIL\n";return 4;}
    int changed=0;
    for(std::uint64_t i=0;i<keys;++i){
        std::string key; std::uint32_t type=0; if(!str(f,key)||!readBytes(f,&type,4)){std::cerr<<"META_FAIL key="<<key<<" type="<<type<<" index="<<i<<"\n";return 5;}
        if((key=="split.count"||key=="split.no") && (type==2 || type==4)){
            const std::streampos pos=f.tellg(); const std::uint32_t v=(key=="split.count")?1u:0u;
            const std::streamoff width = type==2 ? 2 : 4;
            if(!skip(f,static_cast<std::uint64_t>(width))){std::cerr<<"VALUE_FAIL\n";return 6;} f.seekp(pos);
            if(type==2){const std::uint16_t w=static_cast<std::uint16_t>(v); if(!f.write(reinterpret_cast<const char*>(&w),2)){std::cerr<<"WRITE_FAIL\n";return 7;}}
            else if(!f.write(reinterpret_cast<const char*>(&v),4)){std::cerr<<"WRITE_FAIL\n";return 7;}
            f.seekg(pos+width); ++changed;
        } else if(!value(f,type)){std::cerr<<"UNSUPPORTED_META_TYPE="<<type<<" KEY="<<key<<"\n";return 8;}
    }
    std::cout<<"CHANGED="<<changed<<"\n"; return changed?0:9;
}
