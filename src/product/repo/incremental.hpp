#pragma once
#include "../abi/runtime_abi.hpp"
#include "repo_scanner.hpp"
#include <fstream>
#include <iterator>
#include <string>
#include <unordered_map>
namespace rawr::product {

struct FileStamp {
    uint32_t hash = 0;
    uint32_t bytes = 0;
};

struct IncrementalIndex {
    RepoIndex idx;
    std::unordered_map<std::string, FileStamp> stamps;

    bool ingest(const std::string& path) {
        std::ifstream in(path, std::ios::binary);
        if (!in) return false;
        std::string body((std::istreambuf_iterator<char>(in)),
                         std::istreambuf_iterator<char>());
        FileStamp st{};
        st.bytes = (uint32_t)body.size();
        st.hash = RawrFnv1a32(body.data(), st.bytes);
        auto it = stamps.find(path);
        if (it != stamps.end() && it->second.hash == st.hash) return false;
        stamps[path] = st;
        std::vector<Sym> fresh;
        ScanCppFile(path, fresh);
        std::vector<Sym> keep;
        for (const auto& s : idx.symbols)
            if (s.file != path) keep.push_back(s);
        keep.insert(keep.end(), fresh.begin(), fresh.end());
        idx.symbols.swap(keep);
        bool known = false;
        for (const auto& f : idx.files)
            if (f == path) known = true;
        if (!known) idx.files.push_back(path);
        return true;
    }
};

} // namespace rawr::product
