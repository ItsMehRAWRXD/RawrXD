#pragma once
// Native LSP Content-Length framing; no Qt, JSON dependency, or process coupling.
// Parser handles partial headers, partial bodies, multiple frames, and malformed lengths.
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
namespace rawrxd::lsp {
class Framer {
public:
    explicit Framer(size_t maxBytes=16u*1024u*1024u): maxBytes_(maxBytes) {
        if(!maxBytes_) throw std::invalid_argument("zero max frame");
    }
    std::vector<std::string> Feed(std::string_view bytes) {
        if(bytes.size()>maxBytes_+8192 || buffer_.size()>maxBytes_+8192-bytes.size())
            throw std::length_error("LSP receive buffer limit");
        buffer_.append(bytes);
        std::vector<std::string> ready;
        while(true) {
            if(expected_==npos) {
                auto sep=buffer_.find("\r\n\r\n");
                if(sep==std::string::npos) {
                    if(buffer_.size()>8192) throw std::length_error("LSP header too long");
                    break;
                }
                if(sep>8192) throw std::length_error("LSP header too long");
                std::string_view header(buffer_.data(),sep);
                size_t length=npos;
                size_t pos=0;
                while(pos<header.size()) {
                    auto end=header.find("\r\n",pos);
                    if(end==std::string_view::npos) end=header.size();
                    auto line=header.substr(pos,end-pos);
                    constexpr std::string_view prefix="Content-Length:";
                    if(line.size()>=prefix.size() &&
                       line.substr(0,prefix.size())==prefix) {
                        if(length!=npos) throw std::invalid_argument("duplicate Content-Length");
                        auto value=line.substr(prefix.size());
                        while(!value.empty() && value.front()==' ') value.remove_prefix(1);
                        if(value.empty()) throw std::invalid_argument("missing Content-Length");
                        if(value.front()==\u0027+\u0027 || value.front()==\u0027-\u0027)
                            throw std::invalid_argument("signed Content-Length");
                        size_t parsed=0;
                        auto result=std::from_chars(value.data(),value.data()+value.size(),parsed);
                        if(result.ec!=std::errc{} || result.ptr!=value.data()+value.size())
                            throw std::invalid_argument("bad Content-Length");
                        length=parsed;
                    }
                    pos=end==header.size()?end:end+2;
                }
                if(length==npos || length>maxBytes_) throw std::length_error("missing or oversized Content-Length");
                expected_=length;
                buffer_.erase(0,sep+4);
            }
            if(buffer_.size()<expected_) break;
            ready.push_back(buffer_.substr(0,expected_));
            buffer_.erase(0,expected_);
            expected_=npos;
        }
        return ready;
    }
    static std::string Encode(std::string_view json) {
        return "Content-Length: "+std::to_string(json.size())+"\r\n\r\n"+std::string(json);
    }
private:
    static constexpr size_t npos=std::numeric_limits<size_t>::max();
    size_t maxBytes_, expected_=npos;
    std::string buffer_;
};
} // namespace rawrxd::lsp
