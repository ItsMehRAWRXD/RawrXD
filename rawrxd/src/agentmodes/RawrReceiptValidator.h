// RawrReceiptValidator.h — RAWRXD_RAWRRECEIPT_AUTHORITY_001
// Generates and validates receipt files. It cannot invent field values: a
// field is either present in the receipt as measured, or it is missing.
// PASS is computed from the fields that were actually written.
#pragma once
#include <string>
#include <vector>
#include <map>

namespace rawrxd { namespace receiptcheck {

struct Receipt {
    bool                      exists = false;
    std::string               path;
    std::map<std::string, std::string> fields;   // KEY -> value, first wins
    int                       duplicateKeys = 0;
    std::vector<std::string>  keys;              // in file order
};

struct Validation {
    std::string              name;
    std::string              receiptPath;
    std::vector<std::string> required;
    std::vector<std::string> present;
    std::vector<std::string> missing;
    int                      measuredFields = 0;   // numeric/bool values actually written
    int                      literalFields = 0;    // fields present but not measurable
    bool                     receiptExists = false;
    std::string              declaredVerdict;      // VERDICT= as written, if any
    std::string              computedVerdict;      // what the fields justify
    bool                     passComputedFromFields = false;
};

// Read and parse a KEY=VALUE receipt. Missing file yields exists == false.
Receipt load(const std::string& path);

// Check that every field in `required` is present. Nothing is defaulted.
Validation validate(const std::string& name, const std::string& receiptPath,
                    const std::vector<std::string>& required);

// Write RAWRXD_RAWRRECEIPT_AUTHORITY_001 describing a validation. The verdict
// reports whether the validation itself ran, and carries the computed verdict
// of the receipt under inspection as data.
void writeValidationReceipt(const std::string& path, const Validation& v);

}} // namespace rawrxd::receiptcheck
