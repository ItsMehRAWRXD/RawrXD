#include "Deep2B74ReceiptReplay.hpp"
#include <sstream>
#include <cstdlib>

namespace Deep2 {

B74Replay B74ReceiptReplay::parseAndVerify(
    const std::string& text,const std::string& expected) noexcept {

    B74Replay r{};
    r.computedSha256=NoDepSha256::hash(text);
    if(r.computedSha256!=expected) {
        r.failure="SHA256_MISMATCH";return r;
    }

    std::istringstream in(text);
    std::string line;
    while(std::getline(in,line)) {
        const auto p=line.find('=');
        if(p==std::string::npos || p==0) continue;
        r.fields[line.substr(0,p)]=line.substr(p+1);
    }

    auto cert=r.fields.find("CERT");
    if(cert==r.fields.end()) {r.failure="CERT_MISSING";return r;}
    if(cert->second!="PASS") {r.failure="CERT_NOT_PASS";return r;}

    const char* required[]={
        "P10_TPS","MEDIAN_TPS","PHYSICAL_ROOFLINE_TPS",
        "GPU0_FORWARDS","GPU1_FORWARDS","PARITY_ALL","OUTPUT_STABLE_ALL"
    };
    for(const char* k:required) {
        if(r.fields.find(k)==r.fields.end()) {
            r.failure="FIELD_MISSING";return r;
        }
    }

    if(r.fields["PARITY_ALL"]!="1" || r.fields["OUTPUT_STABLE_ALL"]!="1") {
        r.failure="TRUTH_FAIL";return r;
    }
    if(std::strtoull(r.fields["GPU0_FORWARDS"].c_str(),nullptr,10)==0 ||
       std::strtoull(r.fields["GPU1_FORWARDS"].c_str(),nullptr,10)==0) {
        r.failure="BOTH_GPUS";return r;
    }

    r.pass=true;r.failure="PASS";
    return r;
}

B74Regression B74ReceiptReplay::compare(
    const B74Replay& b,const B74Replay& c,
    double maxMed,double maxP10) noexcept {

    B74Regression r{};
    if(!b.pass || !c.pass) {r.failure="REPLAY_HOLD";return r;}

    auto val=[](const B74Replay& x,const char* k)->double {
        auto it=x.fields.find(k);
        return it==x.fields.end()?0.0:std::strtod(it->second.c_str(),nullptr);
    };
    const double bm=val(b,"MEDIAN_TPS"), cm=val(c,"MEDIAN_TPS");
    const double bp=val(b,"P10_TPS"), cp=val(c,"P10_TPS");

    if(bm<=0.0||bp<=0.0){r.failure="BASELINE_ZERO";return r;}
    r.medianTpsDeltaPct=(cm-bm)*100.0/bm;
    r.p10TpsDeltaPct=(cp-bp)*100.0/bp;

    if(r.medianTpsDeltaPct < -maxMed) {
        r.failure="MEDIAN_REGRESSION";return r;
    }
    if(r.p10TpsDeltaPct < -maxP10) {
        r.failure="P10_REGRESSION";return r;
    }
    r.pass=true;r.failure="PASS";
    return r;
}

} // namespace Deep2
