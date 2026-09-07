#pragma once
#include <cstring>
#include <string>
namespace rawr::product {

inline const char* DetectLang(const std::string& path) {
    auto has = [&](const char* s) {
        size_t n = strlen(s);
        return path.size() >= n &&
               _stricmp(path.c_str() + path.size() - n, s) == 0;
    };
    if (has(".cpp") || has(".cc") || has(".cxx") || has(".h") || has(".hpp"))
        return "cpp";
    if (has(".c")) return "c";
    if (has(".asm") || has(".inc")) return "masm";
    if (has(".py")) return "python";
    if (has(".rs")) return "rust";
    if (has(".ts") || has(".tsx") || has(".js")) return "ts";
    if (has(".cmake") || path.find("CMakeLists") != std::string::npos)
        return "cmake";
    return "text";
}

inline bool IndexableLang(const char* lang) {
    return lang && (strcmp(lang, "cpp") == 0 || strcmp(lang, "c") == 0 ||
                    strcmp(lang, "masm") == 0 || strcmp(lang, "h") == 0);
}

} // namespace rawr::product
