// RawrXDGgufReader.cpp
// RAWRXD_GGUF_UNIVERSAL_READER_001
#include "RawrXDGgufReader.hpp"

#include <algorithm>
#include <cmath>

namespace rawrxd {

const char* GgmlTypeName(int32_t t) {
    switch (t) {
        case 0:  return "F32";
        case 1:  return "F16";
        case 2:  return "Q4_0";
        case 3:  return "Q4_1";
        case 6:  return "Q5_0";
        case 7:  return "Q5_1";
        case 8:  return "Q8_0";
        case 9:  return "Q8_1";
        case 10: return "Q2_K";
        case 11: return "Q3_K";
        case 12: return "Q4_K";
        case 13: return "Q5_K";
        case 14: return "Q6_K";
        case 15: return "Q8_K";
        case 16: return "IQ2_XXS";
        case 17: return "IQ2_XS";
        case 18: return "IQ3_XXS";
        case 19: return "IQ1_S";
        case 20: return "IQ4_NL";
        case 21: return "IQ3_S";
        case 22: return "IQ2_S";
        case 23: return "IQ4_XS";
        case 24: return "I8";
        case 25: return "I16";
        case 26: return "I32";
        case 27: return "I64";
        case 28: return "F64";
        case 30: return "BF16";
        case 39: return "MXFP4";
        default: return "UNKNOWN";
    }
}

// Bytes per element for fixed-width dtypes, or 0 for block-quantised dtypes
// whose size depends on the element count rather than a multiple of it.
size_t GgmlTypeSize(int32_t t) {
    switch (t) {
        case 0: return 4;    // F32
        case 1: return 2;    // F16
        case 25: return 2;   // I16
        case 26: return 4;   // I32
        case 27: return 8;   // I64
        case 28: return 8;   // F64
        case 30: return 2;   // BF16
        default: return 0;
    }
}

// Bytes per block for the legacy block-quantised formats. Zero means the size
// is not derivable and the reader refuses rather than guessing; K-quants fall
// in that bucket because their super-block sizes are not uniform enough to
// hard-code safely.
size_t GgmlBlockBytes(int32_t t) {
    switch (t) {
        case 8:  return 34;  // Q8_0 : fp16 d + int8[32]
        case 2:  return 18;  // Q4_0 : fp16 d + int8[16]
        case 3:  return 20;  // Q4_1 : fp16 d + fp16 m + int8[16]
        case 6:  return 22;  // Q5_0 : fp16 d + uint8[5] + nibbles[16]
        case 7:  return 24;  // Q5_1 : fp16 d + fp16 m + ...
        default: return 0;
    }
}

constexpr size_t kLegacyBlockElems = 32;

const char* RoleName(Role r) {
    switch (r) {
        case Role::NONE: return "NONE";
        case Role::TOKEN_EMB: return "TOKEN_EMB";
        case Role::OUTPUT_NORM: return "OUTPUT_NORM";
        case Role::OUTPUT: return "OUTPUT";
        case Role::Q_CUR: return "Q_CUR";
        case Role::K_CUR: return "K_CUR";
        case Role::V_CUR: return "V_CUR";
        case Role::QKV_CUR: return "QKV_CUR";
        case Role::FFN_GATE: return "FFN_GATE";
        case Role::FFN_UP: return "FFN_UP";
        case Role::FFN_DOWN: return "FFN_DOWN";
        case Role::MOE_ROUTER: return "MOE_ROUTER";
        case Role::MOE_GATE_INP: return "MOE_GATE_INP";
        case Role::MOE_EXPERT_GWUP: return "MOE_EXPERT_GWUP";
        case Role::MOE_EXPERT_DOWN: return "MOE_EXPERT_DOWN";
        case Role::MOE_SHARED_GWUP: return "MOE_SHARED_GWUP";
        case Role::MOE_SHARED_DOWN: return "MOE_SHARED_DOWN";
        case Role::MOE_EXP_PROBS: return "MOE_EXP_PROBS";
        case Role::ATTN_NORM: return "ATTN_NORM";
        case Role::FFN_NORM: return "FFN_NORM";
        case Role::SSM_CONV1D: return "SSM_CONV1D";
        case Role::SSM_IN: return "SSM_IN";
        case Role::SSM_OUT: return "SSM_OUT";
        case Role::SSM_A: return "SSM_A";
        case Role::SSM_D: return "SSM_D";
        case Role::SSM_DT_BIAS: return "SSM_DT_BIAS";
        case Role::SSM_NORM: return "SSM_NORM";
        case Role::MLA_WQ_A: return "MLA_WQ_A";
        case Role::MLA_WQ_B: return "MLA_WQ_B";
        case Role::MLA_WKV_A: return "MLA_WKV_A";
        case Role::MLA_WKV_B: return "MLA_WKV_B";
        case Role::MLA_WO: return "MLA_WO";
        case Role::ROPE_CACHE: return "ROPE_CACHE";
        case Role::OUTPUT_BIAS: return "OUTPUT_BIAS";
        case Role::UNKNOWN: return "UNKNOWN";
    }
    return "UNKNOWN";
}

GgufReader::~GgufReader() { Close(); }

void GgufReader::Close() {
    if (fp_) { fclose(fp_); fp_ = nullptr; }
    meta_.clear();
    tensors_.clear();
    why_.clear();
    arch_.clear();
    version_ = 0;
    data_start_ = 0;
    file_size_ = 0;
}

bool GgufReader::readExact(void* p, size_t n) {
    return fread(p, 1, n, fp_) == n;
}

bool GgufReader::Open(const char* path) {
    Close();
    path_ = path ? path : "";
    why_.clear();

    fp_ = fopen(path_.c_str(), "rb");
    if (!fp_) { why_ = "cannot open file"; return false; }
    if (_fseeki64(fp_, 0, SEEK_END) != 0) { why_ = "seek failed"; return false; }
    const __int64 sz = _ftelli64(fp_);
    if (sz <= 0) { why_ = "size unavailable"; return false; }
    file_size_ = (uint64_t)sz;

    if (_fseeki64(fp_, 0, SEEK_SET) != 0) { why_ = "seek failed"; return false; }
    char magic[4];
    if (!readExact(magic, 4) || memcmp(magic, "GGUF", 4) != 0) {
        why_ = "not a GGUF file";
        return false;
    }

    if (!readExact(&version_, 4)) { why_ = "truncated version"; return false; }
    uint64_t n_tensors = 0, n_kv = 0;
    if (!readExact(&n_tensors, 8) || !readExact(&n_kv, 8)) {
        why_ = "truncated counts";
        return false;
    }
    if (n_kv > 1000000 || n_tensors > 10000000) {
        why_ = "implausible counts";
        return false;
    }

    // ---- metadata ----
    for (uint64_t i = 0; i < n_kv; ++i) {
        uint64_t klen = 0;
        if (!readExact(&klen, 8) || klen > (1u << 20)) { why_ = "bad key length"; return false; }
        std::string key((size_t)klen, '\0');
        if (klen && !readExact(&key[0], (size_t)klen)) { why_ = "bad key"; return false; }
        int32_t type = 0;
        if (!readExact(&type, 4)) { why_ = "bad value type"; return false; }

        Value v;
        v.type = type;
        auto scal = [&](auto& out, uint32_t n) {
            return readExact(&out, n) == true;
        };
        switch (type) {
            case 0: { uint8_t x=0; if(!readExact(&x,1)){why_="trunc";return false;} v.u=x; break; }
            case 1: { int8_t x=0; if(!readExact(&x,1)){why_="trunc";return false;} v.u=(uint8_t)x; break; }
            case 2: { uint16_t x=0; if(!readExact(&x,2)){why_="trunc";return false;} v.u=x; break; }
            case 3: { int16_t x=0; if(!readExact(&x,2)){why_="trunc";return false;} v.u=(uint16_t)x; break; }
            case 4: { uint32_t x=0; if(!readExact(&x,4)){why_="trunc";return false;} v.u=x; break; }
            case 5: { int32_t x=0; if(!readExact(&x,4)){why_="trunc";return false;} v.u=(uint32_t)x; break; }
            case 6: { float x=0; if(!readExact(&x,4)){why_="trunc";return false;} v.f=x; break; }
            case 7: { uint8_t x=0; if(!readExact(&x,1)){why_="trunc";return false;} v.b=(x!=0); break; }
            case 8: {
                uint64_t n=0;
                if(!readExact(&n,8)||n>(1u<<22)){why_="bad string len";return false;}
                v.s.assign((size_t)n,'\0');
                if(n && !readExact(&v.s[0],(size_t)n)){why_="trunc string";return false;}
                break;
            }
            case 10: { uint64_t x=0; if(!readExact(&x,8)){why_="trunc";return false;} v.u=x; break; }
            case 11: { int64_t x=0; if(!readExact(&x,8)){why_="trunc";return false;} v.u=(uint64_t)x; break; }
            case 12: { double x=0; if(!readExact(&x,8)){why_="trunc";return false;} v.f=x; break; }
            case 9: {
                uint32_t et=0;
                if(!readExact(&et,4)){why_="bad array type";return false;}
                uint64_t cnt=0;
                if(!readExact(&cnt,8)||cnt>(1u<<24)){why_="bad array count";return false;}
                // Arrays are consumed but not retained; scalar leaves are enough
                // for build planning.
                for (uint64_t j=0;j<cnt;++j) {
                    switch (et) {
                        case 0: case 1: case 7: { uint8_t x; if(!readExact(&x,1)){why_="trunc arr";return false;} break; }
                        case 2: case 3: { uint16_t x; if(!readExact(&x,2)){why_="trunc arr";return false;} break; }
                        case 4: case 5: case 6: { uint32_t x; if(!readExact(&x,4)){why_="trunc arr";return false;} break; }
                        case 8: { uint64_t n; if(!readExact(&n,8)){why_="trunc arr";return false;} if(_fseeki64(fp_,(__int64)n,SEEK_CUR)!=0){why_="bad arr str";return false;} break; }
                        case 10: case 11: case 12: { uint64_t x; if(!readExact(&x,8)){why_="trunc arr";return false;} break; }
                        case 9: { why_="nested arrays unsupported"; return false; }
                        default: why_="unknown array element type"; return false;
                    }
                }
                v.type = 9;
                break;
            }
            default: why_ = "unknown metadata value type"; return false;
        }
        (void)scal;
        meta_[key] = v;
    }

    if (hasKey("general.architecture")) {
        std::string a;
        getString("general.architecture", a);
        arch_ = a;
    }

    // ---- tensor directory ----
    for (uint64_t i = 0; i < n_tensors; ++i) {
        uint64_t nlen = 0;
        if (!readExact(&nlen, 8) || nlen > (1u << 20)) { why_ = "bad tensor name"; return false; }
        GgufTensor t;
        t.name.assign((size_t)nlen, '\0');
        if (nlen && !readExact(&t.name[0], (size_t)nlen)) { why_ = "trunc tensor name"; return false; }
        uint32_t nd = 0;
        if (!readExact(&nd, 4) || nd > 8) { why_ = "bad tensor rank"; return false; }
        t.dims.resize(nd);
        for (uint32_t d = 0; d < nd; ++d)
            if (!readExact(&t.dims[d], 8)) { why_ = "trunc tensor dims"; return false; }
        if (!readExact(&t.type, 4)) { why_ = "trunc tensor type"; return false; }
        if (!readExact(&t.offset, 8)) { why_ = "trunc tensor offset"; return false; }
        if (t.dims.empty()) { why_ = "tensor with no dims"; return false; }

        if (tensors_.find(t.name) != tensors_.end()) { why_ = "duplicate tensor name"; return false; }
        tensors_[t.name] = t;
    }

    // Data begins after the directory, aligned to 32 bytes per the GGUF spec's
    // default. The alignment is itself a metadata key.
    __int64 after_dir = _ftelli64(fp_);
    data_start_ = (uint64_t)after_dir;
    uint64_t align = 32;
    if (!getU64("general.alignment", align)) align = 32;
    if (align > 0) {
        uint64_t pad = (align - (data_start_ % align)) % align;
        data_start_ += pad;
    }

    for (auto& kv : tensors_) {
        GgufTensor& t = kv.second;
        t.abs_offset = data_start_ + t.offset;

        const size_t ts = GgmlTypeSize(t.type);
        const size_t tb = GgmlBlockBytes(t.type);
        if (ts != 0) {
            const uint64_t ne = (uint64_t)t.nelements();
            if (ne > (uint64_t)-1 / ts) { why_ = "tensor too large"; return false; }
            t.nbytes = ne * ts;
        } else if (tb != 0) {
            // Legacy block format: whole 32-element blocks only.
            const uint64_t ne = (uint64_t)t.nelements();
            if (ne % kLegacyBlockElems != 0) {
                why_ = "legacy block tensor not a multiple of 32";
                return false;
            }
            const uint64_t blocks = ne / kLegacyBlockElems;
            if (blocks > (uint64_t)-1 / tb) { why_ = "tensor too large"; return false; }
            t.nbytes = blocks * tb;
        } else {
            // K-quants and unknown dtypes: size is the caller's kernel's
            // business. Mark unknown so readRaw refuses instead of guessing.
            t.nbytes = 0;
        }
    }

    return true;
}

bool GgufReader::hasKey(const char* k) const { return meta_.find(k) != meta_.end(); }

bool GgufReader::getU64(const char* k, uint64_t& out) const {
    auto it = meta_.find(k);
    if (it == meta_.end()) return false;
    if (it->second.type == 9) return false;   // arrays carry no scalar value
    out = it->second.u;
    return true;
}

bool GgufReader::getF32(const char* k, float& out) const {
    auto it = meta_.find(k);
    if (it == meta_.end()) return false;
    if (it->second.type == 9) return false;
    out = (it->second.type == 6 || it->second.type == 12) ? (float)it->second.f : (float)it->second.u;
    return true;
}

bool GgufReader::getBool(const char* k, bool& out) const {
    auto it = meta_.find(k);
    if (it == meta_.end()) return false;
    out = it->second.b || (it->second.type != 7 && it->second.u != 0);
    return true;
}

bool GgufReader::getString(const char* k, std::string& out) const {
    auto it = meta_.find(k);
    if (it == meta_.end()) return false;
    out = it->second.s;
    return true;
}

bool GgufReader::getArchU64(const char* leaf, uint64_t& out) const {
    if (arch_.empty()) return false;
    std::string k = arch_ + "." + leaf;
    return getU64(k.c_str(), out);
}

bool GgufReader::getArchF32(const char* leaf, float& out) const {
    if (arch_.empty()) return false;
    std::string k = arch_ + "." + leaf;
    return getF32(k.c_str(), out);
}

std::string GgufReader::architecture() const { return arch_; }

const GgufTensor* GgufReader::find(const char* name) const {
    auto it = tensors_.find(name);
    return it == tensors_.end() ? nullptr : &it->second;
}

std::string GgufReader::normalizeName(const std::string& n) { return n; }

void GgufReader::layerTensors(int blockIndex, std::vector<const GgufTensor*>& out,
                              const char* suffix) const {
    out.clear();
    const std::string p = "blk." + std::to_string(blockIndex) + "." + suffix;
    for (const auto& kv : tensors_) {
        if (kv.first.rfind(p, 0) == 0 && (kv.first.size() == p.size() ||
                                          kv.first[p.size()] == '.'))
            out.push_back(&kv.second);
    }
    std::sort(out.begin(), out.end(), [](const GgufTensor* a, const GgufTensor* b) {
        return a->name < b->name;
    });
}

void GgufReader::blockIndices(std::vector<int>& out) const {
    out.clear();
    std::vector<int> found;
    for (const auto& kv : tensors_) {
        if (kv.first.rfind("blk.", 0) != 0) continue;
        size_t i = 4, j = i;
        while (j < kv.first.size() && isdigit((unsigned char)kv.first[j])) ++j;
        if (j == i) continue;
        found.push_back(atoi(kv.first.substr(i, j - i).c_str()));
    }
    // Sort and de-duplicate in `found`, then hand it over. Using an iterator
    // into `found` against `out` would be undefined behaviour.
    std::sort(found.begin(), found.end());
    found.erase(std::unique(found.begin(), found.end()), found.end());
    out = found;
}

bool GgufReader::hasSsm() const {
    for (const auto& kv : tensors_)
        if (kv.first.find("ssm_") != std::string::npos) return true;
    return false;
}

bool GgufReader::hasAttention() const {
    for (const auto& kv : tensors_) {
        if (kv.first.find("attn_") != std::string::npos) return true;
        if (kv.first.find(".attn") != std::string::npos) return true;
    }
    return false;
}

bool GgufReader::hasMoe() const {
    for (const auto& kv : tensors_) {
        if (kv.first.find("ffn_gate_exps") != std::string::npos) return true;
        if (kv.first.find("ffn_down_exps") != std::string::npos) return true;
        if (kv.first.find("ffn_up_exps") != std::string::npos) return true;
        if (kv.first.find("exp_probs") != std::string::npos) return true;
    }
    return false;
}

bool GgufReader::readRaw(const GgufTensor& t, void* dst, size_t dstBytes) {
    if (!fp_) { why_ = "not open"; return false; }
    if (t.nbytes == 0) {
        // Unknown size means a block-quantised dtype. The caller must supply
        // the size from its kernel, so refuse rather than read a guess.
        why_ = "tensor size unknown for dtype";
        return false;
    }
    if (dstBytes < t.nbytes) { why_ = "destination too small"; return false; }
    if (t.abs_offset + t.nbytes > file_size_) { why_ = "tensor past end of file"; return false; }
    if (_fseeki64(fp_, (__int64)t.abs_offset, SEEK_SET) != 0) { why_ = "seek failed"; return false; }
    if (!readExact(dst, (size_t)t.nbytes)) { why_ = "read failed"; return false; }
    return true;
}

bool GgufReader::readF32(const GgufTensor& t, std::vector<float>& out) {
    out.assign((size_t)t.nelements(), 0.0f);
    if (t.nelements() == 0) return true;

    const size_t ts = GgmlTypeSize(t.type);
    if (t.type == 0) {                 // F32
        if (!readRaw(t, out.data(), out.size() * sizeof(float))) { out.assign(out.size(), 0.0f); return false; }
        return true;
    }
    if (t.type == 30) {                // BF16: read 16-bit and widen
        std::vector<uint16_t> raw((size_t)t.nelements());
        // nbytes is 2 * elements for BF16, so readRaw works.
        if (!readRaw(t, raw.data(), raw.size() * sizeof(uint16_t))) { out.assign(out.size(), 0.0f); return false; }
        for (size_t i = 0; i < raw.size(); ++i) {
            uint32_t bits = (uint32_t)raw[i] << 16;
            float f;
            memcpy(&f, &bits, 4);
            out[i] = f;
        }
        return true;
    }
    if (t.type == 1) {                 // F16 via a local decode
        std::vector<uint16_t> raw((size_t)t.nelements());
        if (!readRaw(t, raw.data(), raw.size() * sizeof(uint16_t))) { out.assign(out.size(), 0.0f); return false; }
        for (size_t i = 0; i < raw.size(); ++i) {
            const uint32_t h = raw[i];
            const uint32_t sign = (h & 0x8000u) << 16;
            const uint32_t exp  = (h >> 10) & 31u;
            const uint32_t frac = h & 1023u;
            uint32_t bits;
            if (exp == 0) {
                if (frac == 0) bits = sign;
                else {
                    uint32_t m = frac; int e = -14;
                    while ((m & 1024u) == 0u) { m <<= 1; --e; }
                    bits = sign | ((uint32_t)(e + 127) << 23) | ((m & 1023u) << 13);
                }
            } else if (exp == 31) bits = sign | 0x7f800000u | (frac << 13);
            else bits = sign | ((exp + 112u) << 23) | (frac << 13);
            memcpy(&out[i], &bits, 4);
        }
        return true;
    }

    why_ = std::string("readF32 does not decode ") + GgmlTypeName(t.type);
    out.assign((size_t)t.nelements(), 0.0f);
    return false;
}

} // namespace rawrxd
