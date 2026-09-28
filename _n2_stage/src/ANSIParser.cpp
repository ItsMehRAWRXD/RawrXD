// RawrXD native ANSI SGR -> Win32 RichEdit renderer.
// No third-party dependencies.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <richedit.h>
#include <algorithm>
#include <array>
#include <cstdlib>
#include <string>
#include <vector>

namespace RawrXD {

int AppendANSIToRichEdit(HWND h, const std::string& input); // exported declaration

namespace {
struct Style {
    COLORREF fg = RGB(220,220,220);
    COLORREF bg = RGB(0,0,0);
    bool defaultFg = true, defaultBg = true;
    bool bold = false, underline = false, reverse = false;
};

constexpr std::array<COLORREF,16> kAnsi = {
    RGB(0,0,0), RGB(205,49,49), RGB(13,188,121), RGB(229,229,16),
    RGB(36,114,200), RGB(188,63,188), RGB(17,168,205), RGB(229,229,229),
    RGB(102,102,102), RGB(241,76,76), RGB(35,209,139), RGB(245,245,67),
    RGB(59,142,234), RGB(214,112,214), RGB(41,184,219), RGB(255,255,255)
};

COLORREF xterm256(int n) {
    n = std::clamp(n, 0, 255);
    if (n < 16) return kAnsi[(size_t)n];
    if (n >= 232) {
        int v = 8 + (n - 232) * 10;
        return RGB(v,v,v);
    }
    n -= 16;
    int r=n/36, g=(n/6)%6, b=n%6;
    auto c=[](int x){ return x ? 55 + 40*x : 0; };
    return RGB(c(r),c(g),c(b));
}

std::vector<int> params(const std::string& s) {
    std::vector<int> out;
    if (s.empty()) return {0};
    size_t p=0;
    while (p <= s.size()) {
        size_t q=s.find(';',p);
        std::string t=s.substr(p, q==std::string::npos ? q : q-p);
        if (t.empty()) out.push_back(0);
        else {
            char* e=nullptr;
            long v=std::strtol(t.c_str(),&e,10);
            if (e!=t.c_str() && *e=='\0') out.push_back((int)v);
        }
        if (q==std::string::npos) break;
        p=q+1;
    }
    return out.empty() ? std::vector<int>{0} : out;
}

void apply(Style& s, const std::vector<int>& p) {
    for (size_t i=0;i<p.size();++i) {
        int x=p[i];
        if (x==0) s=Style{};
        else if (x==1) s.bold=true;
        else if (x==4) s.underline=true;
        else if (x==7) s.reverse=true;
        else if (x==22) s.bold=false;
        else if (x==24) s.underline=false;
        else if (x==27) s.reverse=false;
        else if (x==39) s.defaultFg=true;
        else if (x==49) s.defaultBg=true;
        else if (30<=x && x<=37) { s.fg=kAnsi[(size_t)(x-30)]; s.defaultFg=false; }
        else if (90<=x && x<=97) { s.fg=kAnsi[(size_t)(8+x-90)]; s.defaultFg=false; }
        else if (40<=x && x<=47) { s.bg=kAnsi[(size_t)(x-40)]; s.defaultBg=false; }
        else if (100<=x && x<=107) { s.bg=kAnsi[(size_t)(8+x-100)]; s.defaultBg=false; }
        else if ((x==38 || x==48) && i+1<p.size()) {
            COLORREF c=RGB(0,0,0); bool ok=false;
            if (p[i+1]==5 && i+2<p.size()) {
                c=xterm256(p[i+2]); i+=2; ok=true;
            } else if (p[i+1]==2 && i+4<p.size()) {
                c=RGB(std::clamp(p[i+2],0,255),
                      std::clamp(p[i+3],0,255),
                      std::clamp(p[i+4],0,255));
                i+=4; ok=true;
            }
            if (ok) {
                if (x==38) { s.fg=c; s.defaultFg=false; }
                else { s.bg=c; s.defaultBg=false; }
            }
        }
    }
}

bool appendRun(HWND h, const std::string& text, const Style& s) {
    if (text.empty()) return true;
    LRESULT n=SendMessageA(h,WM_GETTEXTLENGTH,0,0);
    SendMessageA(h,EM_SETSEL,(WPARAM)n,(LPARAM)n);

    COLORREF fg=s.defaultFg?RGB(220,220,220):s.fg;
    COLORREF bg=s.defaultBg?RGB(0,0,0):s.bg;
    if (s.reverse) std::swap(fg,bg);

    CHARFORMAT2A cf{};
    cf.cbSize=sizeof(cf);
    cf.dwMask=CFM_BOLD|CFM_UNDERLINE|CFM_COLOR|CFM_BACKCOLOR;
    if (s.bold) cf.dwEffects|=CFE_BOLD;
    if (s.underline) cf.dwEffects|=CFE_UNDERLINE;
    cf.crTextColor=fg;
    cf.crBackColor=bg;
    if (!SendMessageA(h,EM_SETCHARFORMAT,SCF_SELECTION,(LPARAM)&cf)) return false;
    SendMessageA(h,EM_REPLACESEL,FALSE,(LPARAM)text.c_str());
    return true;
}
}

int AppendANSIToRichEdit(HWND h, const std::string& input) {
    if (!h || !IsWindow(h)) return -1;
    Style style;
    std::string run;
    auto flush=[&](){
        bool ok=appendRun(h,run,style);
        run.clear();
        return ok;
    };

    for (size_t i=0;i<input.size();) {
        if ((unsigned char)input[i]==0x1B && i+1<input.size() && input[i+1]=='[') {
            size_t j=i+2;
            while (j<input.size() && !((unsigned char)input[j]>=0x40 &&
                                       (unsigned char)input[j]<=0x7E)) ++j;
            if (j==input.size()) { run.append(input.data()+i,input.size()-i); break; }
            if (input[j]=='m') {
                if (!flush()) return -2;
                apply(style,params(input.substr(i+2,j-i-2)));
            }
            i=j+1;
            continue;
        }
        if (input[i]=='\r') {
            if (i+1<input.size() && input[i+1]=='\n') ++i;
            run+="\r\n"; ++i; continue;
        }
        if (input[i]=='\n') { run+="\r\n"; ++i; continue; }
        run.push_back(input[i++]);
    }

    if (!flush()) return -2;
    LRESULT n=SendMessageA(h,WM_GETTEXTLENGTH,0,0);
    SendMessageA(h,EM_SETSEL,(WPARAM)n,(LPARAM)n);
    SendMessageA(h,EM_SCROLLCARET,0,0);
    return 0;
}
} // namespace RawrXD
