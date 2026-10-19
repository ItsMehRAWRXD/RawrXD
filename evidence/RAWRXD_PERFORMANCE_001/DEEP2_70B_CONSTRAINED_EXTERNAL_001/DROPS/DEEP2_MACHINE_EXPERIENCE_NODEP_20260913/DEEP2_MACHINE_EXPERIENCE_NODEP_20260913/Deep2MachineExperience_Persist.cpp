#include "Deep2MachineExperience.hpp"
#include <cstdio>
#include <cstring>

namespace Deep2 { namespace mx {
struct Header { uint32_t magic,ver,bytes,crc; uint64_t epoch,regime; };
bool Save(const Store&s,const char*path){
    if(!path) return false; Store clean=s;
    for(uint32_t i=0;i<clean.used;++i)
        if(!(clean.cells[i].flags&C_TRUTH)) clean.cells[i].flags|=C_QUARANTINE;
    Header h{0x4D583731u,1u,(uint32_t)sizeof(Store),0u,clean.epochHash,clean.regimeHash};
    h.crc=Checksum(&clean,sizeof(clean)); FILE*f=std::fopen(path,"wb"); if(!f)return false;
    bool ok=std::fwrite(&h,sizeof(h),1,f)==1 && std::fwrite(&clean,sizeof(clean),1,f)==1;
    std::fclose(f); return ok;
}
bool Load(Store&s,const char*path,const Epoch&e,const Regime&r){
    FILE*f=std::fopen(path,"rb"); if(!f){Init(s,e,r);return false;} Header h{}; Store tmp{};
    bool ok=std::fread(&h,sizeof(h),1,f)==1 && std::fread(&tmp,sizeof(tmp),1,f)==1;
    std::fclose(f); if(!ok||h.magic!=0x4D583731u||h.ver!=1u||h.bytes!=sizeof(Store)||
                       h.crc!=Checksum(&tmp,sizeof(tmp))){Init(s,e,r);return false;}
    s=tmp; uint64_t eh=HashEpoch(e), rh=HashRegime(r);
    if(eh!=s.epochHash) for(uint32_t i=0;i<s.used;++i) s.cells[i].flags|=C_QUARANTINE;
    else if(rh!=s.regimeHash) for(uint32_t i=0;i<s.used;++i) s.cells[i].flags&=~C_LIVE;
    s.epochHash=eh; s.regimeHash=rh; return true;
}
}}
