// CommaProof.cpp — RAWRXD_COMMAPROOF_DREAMLESS_001
#include "CommaProof.hpp"

#include <cmath>
#include <cstdlib>

namespace Deep2 {
namespace proof {

bool CommaProof::add(std::string key, std::string value, Source s) {
    if (key.empty()) return false;
    // A prediction cannot enter here. The only source accepted is Observed;
    // anything else is refused at the call rather than flagged later.
    if (s != Source::Observed && s != Source::Unknown) return false;

    for (auto& f : facts_) {
        if (f.key == key) {           // last write wins, but the source rule holds
            f.value = (s == Source::Unknown) ? std::string("NA") : value;
            f.source = s;
            return true;
        }
    }
    Fact f;
    f.key = std::move(key);
    f.value = (s == Source::Unknown) ? std::string("NA") : value;
    f.source = s;
    facts_.push_back(std::move(f));
    return true;
}

bool CommaProof::observe(std::string key, std::string value) {
    return add(std::move(key), std::move(value), Source::Observed);
}

bool CommaProof::recordUnknown(std::string key) {
    return add(std::move(key), std::string("NA"), Source::Unknown);
}

bool CommaProof::has(const std::string& key) const {
    return find(key) != nullptr;
}

const Fact* CommaProof::find(const std::string& key) const {
    for (const auto& f : facts_)
        if (f.key == key) return &f;
    return nullptr;
}

std::string CommaProof::get(const std::string& key) const {
    const Fact* f = find(key);
    return f ? f->value : std::string("NA");
}

std::uint64_t CommaProof::getU64(const std::string& key) const {
    const Fact* f = find(key);
    if (!f || f->value == "NA" || f->value.empty()) return 0;
    return std::strtoull(f->value.c_str(), nullptr, 10);
}

std::string CommaProof::toLine() const {
    std::string out;
    for (std::size_t i = 0; i < facts_.size(); ++i) {
        if (i) out += ",";
        out += facts_[i].key;
        out += "=";
        out += facts_[i].value.empty() ? std::string("NA") : facts_[i].value;
    }
    return out;
}

CommaProof::Audit CommaProof::audit() const {
    Audit a;
    a.factCount = (std::uint32_t)facts_.size();
    for (const auto& f : facts_) {
        if (f.source == Source::Observed) ++a.observed; else ++a.unknown;
        if (f.value.empty()) {
            ++a.emptyValues;
            if (a.firstProblem.empty())
                a.firstProblem = "EMPTY_VALUE:" + f.key;
        }
        if (f.key.empty()) {
            if (a.firstProblem.empty()) a.firstProblem = "EMPTY_KEY";
        }
        // Anything other than an integral key=value is a malformed atom.
        if (f.key.find('=') != std::string::npos ||
            f.value.find(',') != std::string::npos) {
            if (a.firstProblem.empty())
                a.firstProblem = "MALFORMED_ATOM:" + f.key;
        }
    }
    a.valid = (a.factCount > 0) && a.emptyValues == 0 && a.firstProblem.empty();
    return a;
}

// ---------------------------------------------------------------------------
// Endpoint declaration. Declared BEFORE execution and then frozen, so the
// requirement set cannot be widened once reality is known.
// ---------------------------------------------------------------------------
bool CommaProof::declareEndpoint(std::string endpoint,
                                 const std::vector<Requirement>& required) {
    if (requirementsFrozen_) return false;
    if (endpoint.empty()) return false;
    endpoint_  = std::move(endpoint);
    required_  = required;
    requirementsFrozen_ = true;
    return true;
}

CommaProof::Verdict CommaProof::verdict() const {
    Verdict v;
    v.endpoint = endpoint_;
    v.required = (std::uint32_t)required_.size();

    for (const auto& r : required_) {
        const Fact* f = find(r.key);
        ReqState st;
        std::string got;

        if (!f) {
            // MISSING_FACT_REMAINS_UNKNOWN. Not a pass, and explicitly not a
            // failure either: it simply was not established.
            st = ReqState::UNKNOWN;
            got = "ABSENT";
        } else if (f->value == "NA" || f->source == Source::Unknown) {
            st = ReqState::UNKNOWN;
            got = "NA";
        } else if (r.numeric) {
            const double a = std::strtod(f->value.c_str(), nullptr);
            const double b = std::strtod(r.expected.c_str(), nullptr);
            const bool ok = r.numericGreater ? (a > b) : (a == b);
            st = ok ? ReqState::PASS : ReqState::FAIL;
            got = f->value;
        } else {
            const bool ok = (f->value == r.expected);
            st = ok ? ReqState::PASS : ReqState::FAIL;
            got = f->value;
        }

        switch (st) {
            case ReqState::PASS:    ++v.passed; break;
            case ReqState::FAIL:    ++v.failed; break;
            case ReqState::UNKNOWN: ++v.unknown; break;
        }
        if (st != ReqState::PASS && v.firstUnsatisfied.empty())
            v.firstUnsatisfied = r.key + "=" + got + " (need " + r.expected + ")";

        v.lines.push_back(r.key + "=" + got +
                          (st == ReqState::PASS ? " PASS"
                           : st == ReqState::FAIL ? " FAIL" : " UNKNOWN"));
    }

    // REACHED requires every requirement to have PASSED. A single UNKNOWN makes
    // the verdict indeterminate, and an indeterminate verdict is NOT a pass.
    v.reached = (v.required > 0) && (v.passed == v.required);
    v.indeterminate = (v.unknown > 0);
    return v;
}

bool CommaProof::parse(const std::string& line, CommaProof& out) {
    out = CommaProof();
    std::size_t i = 0;
    while (i <= line.size()) {
        const std::size_t comma = line.find(',', i);
        const std::string atom = line.substr(
            i, (comma == std::string::npos ? line.size() : comma) - i);
        if (atom.empty()) return false;
        const std::size_t eq = atom.find('=');
        if (eq == std::string::npos || eq == 0) return false;
        const std::string k = atom.substr(0, eq);
        const std::string v = atom.substr(eq + 1);
        if (!out.observe(k, v)) return false;
        if (comma == std::string::npos) break;
        i = comma + 1;
    }
    return !out.facts().empty();
}

} // namespace proof
} // namespace Deep2