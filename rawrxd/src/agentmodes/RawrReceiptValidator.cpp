// RawrReceiptValidator.cpp — RAWRXD_RAWRRECEIPT_AUTHORITY_001
#include "agentmodes/RawrReceiptValidator.h"
#include "deep2/ReceiptAuthority.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <sstream>

namespace rawrxd { namespace receiptcheck {

static std::string trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

// A value is "measured" when it is a number or a 0/1 flag, i.e. something a
// run could actually have produced. Prose and statuses are literals.
static bool looksMeasured(const std::string& v) {
    if (v.empty()) return false;
    if (v == "0" || v == "1") return true;
    size_t i = (v[0] == '-' || v[0] == '+') ? 1 : 0;
    if (i >= v.size()) return false;
    bool digit = false, dot = false;
    for (; i < v.size(); ++i) {
        if (std::isdigit(static_cast<unsigned char>(v[i]))) { digit = true; continue; }
        if (v[i] == '.' && !dot) { dot = true; continue; }
        return false;
    }
    return digit;
}

Receipt load(const std::string& path) {
    Receipt r;
    r.path = path;
    std::ifstream in(path, std::ios::binary);
    if (!in) return r;
    r.exists = true;

    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;
        const size_t eq = t.find('=');
        if (eq == std::string::npos) continue;
        const std::string k = trim(t.substr(0, eq));
        const std::string v = trim(t.substr(eq + 1));
        if (k.empty()) continue;
        if (r.fields.count(k)) { ++r.duplicateKeys; continue; }  // first wins
        r.fields.emplace(k, v);
        r.keys.push_back(k);
    }
    return r;
}

Validation validate(const std::string& name, const std::string& receiptPath,
                    const std::vector<std::string>& required) {
    Validation v;
    v.name = name;
    v.receiptPath = receiptPath;
    v.required = required;

    const Receipt r = load(receiptPath);
    v.receiptExists = r.exists;
    if (!r.exists) {
        v.missing = required;
        v.computedVerdict = "RECEIPT_MISSING";
        return v;
    }

    for (const auto& k : required) {
        const auto it = r.fields.find(k);
        if (it == r.fields.end()) { v.missing.push_back(k); continue; }
        v.present.push_back(k);
        if (looksMeasured(it->second)) ++v.measuredFields; else ++v.literalFields;
    }

    const auto dv = r.fields.find("VERDICT");
    if (dv != r.fields.end()) v.declaredVerdict = dv->second;

    // The computed verdict never consults the declared one. It is derived from
    // whether the evidence required to back a PASS is actually present.
    if (!v.missing.empty())      v.computedVerdict = "INCOMPLETE_FIELDS";
    else if (v.measuredFields == 0) v.computedVerdict = "NO_MEASURED_EVIDENCE";
    else                         v.computedVerdict = "COMPLETE";

    // A declared PASS that the fields do not support is a false PASS, and this
    // mode reports it as such rather than passing it through.
    v.passComputedFromFields = (v.computedVerdict == "COMPLETE") &&
                               (v.declaredVerdict != "PASS" ||
                                v.measuredFields > 0);
    return v;
}

void writeValidationReceipt(const std::string& path, const Validation& v) {
    receipt::beginGate(path, "RAWRXD_RAWRRECEIPT_AUTHORITY_001");
    receipt::writeKeyValue(path, "RECEIPT_NAME", v.name);
    receipt::writeKeyValue(path, "RECEIPT_PATH", v.receiptPath);
    receipt::writeKeyValueInt(path, "RECEIPT_EXISTS", v.receiptExists ? 1 : 0);
    receipt::writeKeyValueInt(path, "FIELDS_REQUIRED", (int64_t)v.required.size());
    receipt::writeKeyValueInt(path, "FIELDS_PRESENT",  (int64_t)v.present.size());
    receipt::writeKeyValueInt(path, "FIELDS_MISSING",  (int64_t)v.missing.size());
    receipt::writeKeyValueInt(path, "MEASURED_FIELDS", v.measuredFields);
    receipt::writeKeyValueInt(path, "LITERAL_FIELDS",  v.literalFields);
    for (size_t i = 0; i < v.missing.size() && i < 50; ++i) {
        receipt::writeKeyValue(path, "MISSING_" + std::to_string(i + 1), v.missing[i]);
    }
    receipt::writeKeyValue(path, "DECLARED_VERDICT", v.declaredVerdict.empty() ? "(none)" : v.declaredVerdict);
    receipt::writeKeyValue(path, "COMPUTED_VERDICT", v.computedVerdict);
    receipt::writeKeyValueInt(path, "PASS_COMPUTED_FROM_FIELDS", v.passComputedFromFields ? 1 : 0);

    // This mode's own verdict: the validation ran and produced a computed
    // verdict. It is not a claim about the receipt under inspection.
    const bool ran = v.receiptExists;
    receipt::endGate(path, ran ? "VALIDATED" : "RECEIPT_MISSING");
}

}} // namespace rawrxd::receiptcheck
