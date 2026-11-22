#pragma once
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <locale>
#include <sstream>
#include <string>
#include <vector>

namespace Deep2 { namespace ReapState {
// Same canonical suffix as GGUFLoader. The calibration CLI accepts the first
// shard, never an arbitrary member as the checkpoint identity anchor.
inline bool ShardPaths(const std::filesystem::path& first,
                       std::vector<std::filesystem::path>& paths) {
    paths.clear();const auto name=first.filename().string();
    if(name.size()<20 || name.substr(name.size()-14,4)!="-of-") {
        paths.push_back(first);return true;
    }
    const auto marker=name.size()-20;
    auto extension=name.substr(name.size()-5);
    for(char& c:extension)if(c>='A'&&c<='Z')c=static_cast<char>(c-'A'+'a');
    if(extension!=".gguf"||name.substr(marker,7)!="-00001-")return false;
    const auto countText=name.substr(marker+10,5);
    if(countText.find_first_not_of("0123456789")!=std::string::npos)return false;
    unsigned count=0;for(char c:countText)count=count*10+static_cast<unsigned>(c-'0');
    if(!count||count>4096)return false;
    paths.push_back(first);
    for(unsigned i=2;i<=count;++i){
        std::ostringstream n;n.imbue(std::locale::classic());
        n<<name.substr(0,marker)<<'-'<<std::setw(5)<<std::setfill('0')<<i<<"-of-"<<countText<<".gguf";
        paths.push_back(first.parent_path()/n.str());
    }
    return true;
}
} } // namespace Deep2::ReapState
