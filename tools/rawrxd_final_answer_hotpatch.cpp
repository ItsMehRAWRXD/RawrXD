// RawrXD final-answer hotpatch: C++17, no third-party dependencies.
// Build: cl /nologo /std:c++17 /EHsc /W4 rawrxd_final_answer_hotpatch.cpp
// Usage: rawrxd_final_answer_hotpatch.exe [model] [prompt]
// Requires an existing local Ollama server on 127.0.0.1:11434.
// Windows-only WinHTTP transport. Never invents an answer from reasoning text.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#pragma comment(lib, "winhttp.lib")

static std::string escape_json(const std::string& s) {
    std::string o;
    for (unsigned char c : s) {
        switch (c) {
        case '"': o += "\\\""; break;
        case '\\': o += "\\\\"; break;
        case '\n': o += "\\n"; break;
        case '\r': o += "\\r"; break;
        case '\t': o += "\\t"; break;
        default:
            if (c < 0x20) {
                static const char* h = "0123456789abcdef";
                o += "\\u00"; o += h[c >> 4]; o += h[c & 15];
            } else o += char(c);
        }
    }
    return o;
}

// Minimal JSON scanner: supports objects, strings, arrays, numbers, booleans, null.
// It only extracts top-level `message.content` and `done_reason` from Ollama responses.
struct Json {
    const std::string& s;
    size_t i = 0;
    explicit Json(const std::string& x) : s(x) {}
    void ws() { while (i < s.size() && (s[i]==' ' || s[i]=='\t' || s[i]=='\r' || s[i]=='\n')) ++i; }
    void expect(char c) { ws(); if (i >= s.size() || s[i++] != c) throw std::runtime_error("Invalid JSON"); }
    std::string str() {
        expect('"'); std::string out;
        while (i < s.size()) {
            unsigned char c = static_cast<unsigned char>(s[i++]);
            if (c == '"') return out;
            if (c != '\\') { if (c < 0x20) throw std::runtime_error("Invalid JSON string"); out += char(c); continue; }
            if (i >= s.size()) throw std::runtime_error("Invalid escape");
            char e = s[i++];
            switch (e) {
            case '"': out += '"'; break; case '\\': out += '\\'; break; case '/': out += '/'; break;
            case 'n': out += '\n'; break; case 'r': out += '\r'; break; case 't': out += '\t'; break;
            case 'b': out += '\b'; break; case 'f': out += '\f'; break;
            case 'u': {
                if (i+4 > s.size()) throw std::runtime_error("Invalid unicode escape");
                unsigned code = 0;
                for (int k=0;k<4;++k) {
                    char h=s[i++]; code <<= 4;
                    if (h>='0'&&h<='9') code+=h-'0';
                    else if(h>='a'&&h<='f') code+=h-'a'+10;
                    else if(h>='A'&&h<='F') code+=h-'A'+10;
                    else throw std::runtime_error("Invalid unicode escape");
                }
                // Preserve Unicode scalars as UTF-8 (surrogate pairs are uncommon in these fields).
                if (code < 0x80) out += char(code);
                else if (code < 0x800) { out += char(0xc0 | (code>>6)); out += char(0x80 | (code&63)); }
                else { out += char(0xe0 | (code>>12)); out += char(0x80 | ((code>>6)&63)); out += char(0x80 | (code&63)); }
                break;
            }
            default: throw std::runtime_error("Invalid JSON escape");
            }
        }
        throw std::runtime_error("Unterminated string");
    }
    void skip() {
        ws(); if (i>=s.size()) throw std::runtime_error("Truncated JSON");
        char c=s[i];
        if(c=='"') { (void)str(); return; }
        if(c=='{' || c=='[') {
            char end=c=='{'?'}':']'; ++i; ws();
            if(i<s.size()&&s[i]==end) {++i;return;}
            while(true) {
                if(c=='{') { (void)str(); expect(':'); }
                skip(); ws();
                if(i>=s.size()) throw std::runtime_error("Truncated JSON");
                if(s[i]==end) {++i;return;}
                expect(',');
            }
        }
        while(i<s.size() && s[i]!=',' && s[i]!=']' && s[i]!='}' && s[i]!=' ' && s[i]!='\n' && s[i]!='\r' && s[i]!='\t') ++i;
    }
    std::string field(const std::string& name) {
        expect('{'); ws(); if(i<s.size()&&s[i]=='}') {++i;return {};}
        for(;;) {
            std::string key=str(); expect(':'); ws();
            if(key==name) {
                if(i<s.size()&&s[i]=='"') return str();
                if(i<s.size()&&s[i]=='{') { // return raw nested object
                    size_t begin=i; skip(); return s.substr(begin,i-begin);
                }
                skip(); return {};
            }
            skip(); ws();
            if(i>=s.size()) throw std::runtime_error("Truncated JSON");
            if(s[i++]=='}') return {};
        }
    }
};

struct Handle {
    HINTERNET h = nullptr;
    explicit Handle(HINTERNET x=nullptr):h(x){}
    ~Handle(){if(h) WinHttpCloseHandle(h);}
    Handle(const Handle&)=delete; Handle& operator=(const Handle&)=delete;
};

static std::string post(const std::string& body) {
    Handle session(WinHttpOpen(L"RawrXD-FinalAnswer/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if(!session.h) throw std::runtime_error("WinHttpOpen failed");
    WinHttpSetTimeouts(session.h,10000,10000,30000,120000);
    Handle connection(WinHttpConnect(session.h,L"127.0.0.1",11434,0));
    if(!connection.h) throw std::runtime_error("WinHttpConnect failed");
    Handle request(WinHttpOpenRequest(connection.h,L"POST",L"/api/chat",nullptr,
                                      WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,0));
    if(!request.h) throw std::runtime_error("WinHttpOpenRequest failed");
    const wchar_t* headers=L"Content-Type: application/json\r\n";
    if(!WinHttpSendRequest(request.h,headers,(DWORD)-1L,(void*)body.data(),
                           (DWORD)body.size(),(DWORD)body.size(),0))
        throw std::runtime_error("WinHttpSendRequest failed");
    if(!WinHttpReceiveResponse(request.h,nullptr)) throw std::runtime_error("WinHttpReceiveResponse failed");
    DWORD status=0,len=sizeof(status);
    if(!WinHttpQueryHeaders(request.h,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX,&status,&len,WINHTTP_NO_HEADER_INDEX))
        throw std::runtime_error("Cannot read HTTP status");
    if(status!=200) throw std::runtime_error("Ollama HTTP " + std::to_string(status));
    std::string response;
    for(;;) {
        char buf[8192]; DWORD read=0;
        if(!WinHttpReadData(request.h,buf,sizeof(buf),&read)) throw std::runtime_error("WinHttpReadData failed");
        if(!read) break;
        if(response.size()+read > 32*1024*1024) throw std::runtime_error("Response too large");
        response.append(buf,read);
    }
    return response;
}

struct Result { std::string content, thinking, done_reason; };
static Result parse(const std::string& response) {
    Json top(response);
    std::string message=top.field("message");
    Json top2(response);
    std::string reason=top2.field("done_reason");
    if(message.empty()) throw std::runtime_error("Missing message object");
    Json m1(message),m2(message);
    return {m1.field("content"),m2.field("thinking"),reason};
}
static Result call(const std::string& model,const std::string& prompt,int max_tokens) {
    std::string body="{\"model\":\""+escape_json(model)+"\",\"messages\":[{\"role\":\"user\",\"content\":\""+
                     escape_json(prompt)+"\"}],\"stream\":false,\"think\":false,\"keep_alive\":\"30m\",\"options\":{\"num_ctx\":4096,\"num_predict\":"+
                     std::to_string(max_tokens)+",\"temperature\":0}}";
    return parse(post(body));
}
int main(int argc,char** argv) {
    try {
        std::string model=argc>1?argv[1]:"qwen3next-reap128-1m:latest";
        std::string prompt=argc>2?argv[2]:"Reply with exactly: Hello";
        Result first=call(model,prompt,256);
        if(!first.content.empty() && first.done_reason!="length") {
            std::cout << first.content << '\n'; return 0;
        }
        std::cerr << "RAWRXD_PRIMARY_NO_FINAL content_bytes=" << first.content.size()
                  << " thinking_bytes=" << first.thinking.size()
                  << " done_reason=" << first.done_reason << '\n';
        // Single bounded retry with explicit instruction. Do NOT republish thinking as final.
        std::string recovery="Do not explain your reasoning or write a thinking section. "
                             "Output only the final answer to the following request. "
                             "If unable, output ERROR_UNABLE_TO_ANSWER. Request: " + prompt;
        Result second=call(model,recovery,128);
        if(!second.content.empty() && second.done_reason!="length") {
            std::cout << second.content << '\n';
            std::cerr << "RAWRXD_FINAL_RECOVERED\n";
            return 0;
        }
        std::cerr << "RAWRXD_FINAL_FAILED recovery_content_bytes=" << second.content.size()
                  << " recovery_thinking_bytes=" << second.thinking.size()
                  << " done_reason=" << second.done_reason << '\n';
        return 2;
    } catch(const std::exception& e) {
        std::cerr << "RAWRXD_TRANSPORT_OR_PARSE_ERROR " << e.what() << '\n';
        return 3;
    }
}
