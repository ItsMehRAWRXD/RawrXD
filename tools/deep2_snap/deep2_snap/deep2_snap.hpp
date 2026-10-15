#pragma once
// Deep2 SNAP: dependency-free C++20 incremental tool protocol and cancellation.
// The host must supply the model token callback, tool executor and OS process cancellation.
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace deep2::snap {
enum class Reason { none, tool_ready, finish, eos, cancelled, invalid, token_limit, deadline, output_limit };
struct Command { std::string verb; std::string payload; };
struct Result { Reason reason=Reason::none; std::optional<Command> command; size_t tokens=0; std::string diagnostic; };
// Wire format: TOOL <verb> <byte-count>\n<exactly N payload bytes>\nEND_TOOL\n
// Finish uses TOOL finish 0\n\nEND_TOOL\n. Length framing prevents accidental
// dispatch on an incomplete multi-line patch.
class Parser {
    enum class Phase { header, payload, trailer, done, failed };
    Phase phase_=Phase::header;
    std::string header_, payload_, trailer_, verb_, error_;
    size_t expected_=0, max_payload_;
    bool parse_header() {
        if (header_.size()<7 || header_.compare(0,5,"TOOL ")!=0) {error_="expected TOOL header";return false;}
        auto sep=header_.find(' ',5);
        if(sep==std::string::npos){error_="missing length";return false;}
        verb_=header_.substr(5,sep-5);
        if(verb_!="read" && verb_!="write" && verb_!="build" && verb_!="test" && verb_!="finish") {error_="unknown verb";return false;}
        auto digits=std::string_view(header_).substr(sep+1);
        if(digits.empty()){error_="empty length";return false;}
        size_t n=0;
        for(char c:digits){ if(c<'0'||c>'9'){error_="invalid length";return false;} size_t d=static_cast<size_t>(c-'0'); if(n>(max_payload_-d)/10 || d>max_payload_){error_="payload too large";return false;} n=n*10+d; }
        expected_=n;
        return true;
    }
public:
    explicit Parser(size_t max_payload=1024*1024):max_payload_(max_payload){}
    Reason feed(std::string_view bytes){
        for(char c:bytes){
            switch(phase_){
            case Phase::header:
                if(c=='\n') {if(!parse_header()){phase_=Phase::failed;return Reason::invalid;} phase_=Phase::payload;}
                else {if(header_.size()>=128 || c=='\r'){error_="header invalid/too long";phase_=Phase::failed;return Reason::invalid;}header_+=c;}
                break;
            case Phase::payload:
                if(payload_.size()<expected_) payload_+=c;
                else {if(c!='\n'){error_="missing payload newline";phase_=Phase::failed;return Reason::invalid;}phase_=Phase::trailer;}
                break;
            case Phase::trailer:
                trailer_+=c;
                if(trailer_.size()>9 || std::string_view("END_TOOL\n").substr(0,trailer_.size())!=trailer_){error_="invalid terminator";phase_=Phase::failed;return Reason::invalid;}
                if(trailer_=="END_TOOL\n"){phase_=Phase::done;return verb_=="finish"?Reason::finish:Reason::tool_ready;}
                break;
            case Phase::done: error_="trailing output";phase_=Phase::failed;return Reason::invalid;
            case Phase::failed:return Reason::invalid;
            }
        }
        return Reason::none;
    }
    std::optional<Command> command() const {if(phase_!=Phase::done)return std::nullopt;return Command{verb_,payload_};}
    const std::string& error()const{return error_;}
    void reset(){*this=Parser(max_payload_);}
};
struct Limits {size_t max_tokens=300;size_t max_output_bytes=1024*1024;std::chrono::steady_clock::time_point deadline=std::chrono::steady_clock::time_point::max();};
class Controller {
    Parser parser_;Limits limits_;std::atomic<bool> cancelled_{false};size_t tokens_=0, bytes_=0;
public:
    explicit Controller(Limits limits={},size_t max_payload=1024*1024):parser_(max_payload),limits_(limits){}
    void cancel() noexcept {cancelled_.store(true,std::memory_order_release);}
    bool cancelled()const noexcept{return cancelled_.load(std::memory_order_acquire);}
    Result before_decode()const {
        if(cancelled())return {Reason::cancelled,{},tokens_,"cancelled"};
        if(std::chrono::steady_clock::now()>=limits_.deadline)return {Reason::deadline,{},tokens_,"deadline exceeded"};
        if(tokens_>=limits_.max_tokens)return {Reason::token_limit,{},tokens_,"token limit"};
        return {Reason::none,{},tokens_,{}};
    }
    Result on_token(std::string_view decoded,bool eos=false){
        if(auto r=before_decode();r.reason!=Reason::none)return r;
        ++tokens_;
        if(eos)return {Reason::eos,{},tokens_,"eos"};
        if(decoded.size()>limits_.max_output_bytes-bytes_)return {Reason::output_limit,{},tokens_,"output limit"};
        bytes_+=decoded.size();
        auto reason=parser_.feed(decoded);
        if(reason==Reason::invalid)return {reason,{},tokens_,parser_.error()};
        if(reason==Reason::tool_ready || reason==Reason::finish)return {reason,parser_.command(),tokens_,{}};
        return {Reason::none,{},tokens_,{}};
    }
};
// Driver must call before_decode at each decode boundary and on_token for
// each fully detokenized token fragment. Do not call tools inside GPU callbacks.
// Upon tool_ready: return to host, validate authorization, then execute.
}
