// Win32IDE_SyntaxHighlight.cpp — syntax highlight helpers (shared with EditorEngine)
#include <windows.h>
#include <string>
#include <vector>

namespace RawrXD::IDE {

// Token types
enum class SynTok { Normal, Keyword, String, Comment, Number, Preprocessor, Type };

static const char* s_kw[] = {
    "auto","break","case","catch","class","const","constexpr","continue","default",
    "delete","do","double","else","enum","explicit","extern","false","float","for",
    "friend","goto","if","inline","int","long","namespace","new","noexcept","nullptr",
    "operator","override","private","protected","public","register","return","short",
    "signed","sizeof","static","static_assert","struct","switch","template","this",
    "thread_local","throw","true","try","typedef","typename","union","unsigned",
    "using","virtual","void","volatile","while","decltype","alignas","alignof",
    "final","import","export","module","co_await","co_return","co_yield", nullptr
};

static const char* s_types[] = {
    "bool","char","char8_t","char16_t","char32_t","wchar_t","size_t","ptrdiff_t",
    "int8_t","int16_t","int32_t","int64_t","uint8_t","uint16_t","uint32_t","uint64_t",
    "HWND","HINSTANCE","HANDLE","DWORD","WORD","BYTE","BOOL","LRESULT","WPARAM","LPARAM",
    "HFONT","HDC","HBRUSH","HBITMAP","COLORREF","RECT","POINT","SIZE","MSG", nullptr
};

static bool matchWord(const char** list, const std::string& w)
{
    for (int i = 0; list[i]; ++i) if (w == list[i]) return true;
    return false;
}

struct SynToken { int start, len; SynTok type; };

std::vector<SynToken> SyntaxHighlight_Tokenize(const std::string& line)
{
    std::vector<SynToken> out;
    int n = (int)line.size(), i = 0;
    while (i < n) {
        if (i+1 < n && line[i]=='/' && line[i+1]=='/') { out.push_back({i,n-i,SynTok::Comment}); break; }
        if (line[i]=='#') { out.push_back({i,n-i,SynTok::Preprocessor}); break; }
        if (line[i]=='"' || line[i]=='\'') {
            char q=line[i]; int j=i+1;
            while (j<n && line[j]!=q) { if(line[j]=='\\') ++j; ++j; }
            if(j<n) ++j;
            out.push_back({i,j-i,SynTok::String}); i=j; continue;
        }
        if (isdigit((unsigned char)line[i])) {
            int j=i;
            while(j<n && (isalnum((unsigned char)line[j])||line[j]=='.'||line[j]=='x'||line[j]=='X')) ++j;
            out.push_back({i,j-i,SynTok::Number}); i=j; continue;
        }
        if (isalpha((unsigned char)line[i])||line[i]=='_') {
            int j=i;
            while(j<n && (isalnum((unsigned char)line[j])||line[j]=='_')) ++j;
            std::string w=line.substr(i,j-i);
            SynTok t = SynTok::Normal;
            if (matchWord(s_kw,    w)) t = SynTok::Keyword;
            else if (matchWord(s_types, w)) t = SynTok::Type;
            out.push_back({i,j-i,t}); i=j; continue;
        }
        out.push_back({i,1,SynTok::Normal}); ++i;
    }
    return out;
}

COLORREF SyntaxHighlight_Color(SynTok t)
{
    switch(t) {
        case SynTok::Keyword:      return RGB(86,  156, 214);
        case SynTok::Type:         return RGB(78,  201, 176);
        case SynTok::String:       return RGB(206, 145, 120);
        case SynTok::Comment:      return RGB(106, 153, 85);
        case SynTok::Number:       return RGB(181, 206, 168);
        case SynTok::Preprocessor: return RGB(155, 155, 100);
        default:                   return RGB(212, 212, 212);
    }
}

} // namespace RawrXD::IDE
