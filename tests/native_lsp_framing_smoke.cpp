#include "../src/win32app/native/NativeLspFraming.hpp"
#include <cassert>
#include <iostream>
#include <stdexcept>
int main() {
    using rawrxd::lsp::Framer;
    Framer p(1024);
    const auto a=Framer::Encode(R"({"jsonrpc":"2.0","id":1})");
    const auto b=Framer::Encode(R"({"jsonrpc":"2.0","id":2})");
    auto x=p.Feed(a.substr(0,7)); assert(x.empty());
    x=p.Feed(a.substr(7)+b);
    assert(x.size()==2 && x[0].find("\"id\":1")!=std::string::npos);
    assert(x[1].find("\"id\":2")!=std::string::npos);
    Framer q(5);
    bool threw=false;
    try { (void)q.Feed("Content-Length: 99\r\n\r\n"); }
    catch(const std::length_error&){threw=true;}
    assert(threw);
    threw=false;
    try { (void)q.Feed("Content-Length: 1\r\nContent-Length: 1\r\n\r\na"); }
    catch(const std::invalid_argument&){threw=true;}
    assert(threw);
    for (const auto* signedHeader : {"Content-Length: +1\\r\\n\\r\\na", "Content-Length: -1\\r\\n\\r\\na"}) {
        Framer signedFramer(1024);
        bool signedRejected=false;
        try { (void)signedFramer.Feed(signedHeader); }
        catch(const std::invalid_argument&) { signedRejected=true; }
        assert(signedRejected);
    }
    std::cout<<"NATIVE_LSP_FRAMING_SMOKE_PASS\n";
}
