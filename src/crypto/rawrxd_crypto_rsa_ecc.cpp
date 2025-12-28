/**
 * RSA and ECDSA Implementation for JWT Signature Verification
 */

#include "rawrxd_crypto.h"
#include <stdexcept>
#include <cstring>

namespace RawrXD {
namespace Crypto {

// ============================================================
// RSA PUBLIC KEY OPERATIONS
// ============================================================

RSAPublicKey::RSAPublicKey() : n_(0), e_(65537) {}

RSAPublicKey::RSAPublicKey(const BigInt& n, const BigInt& e) : n_(n), e_(e) {}

bool RSAPublicKey::loadFromJWK(const std::string& n_base64url,
                                const std::string& e_base64url) {
    try {
        auto n_bytes = Base64Url::decode(n_base64url);
        auto e_bytes = Base64Url::decode(e_base64url);
        
        n_ = BigInt(n_bytes);
        e_ = BigInt(e_bytes);
        
        return !n_.isZero() && !e_.isZero();
    } catch (...) {
        return false;
    }
}

BigInt RSAPublicKey::encrypt(const BigInt& plaintext) const {
    return plaintext.modPow(e_, n_);
}

size_t RSAPublicKey::getModulusBits() const {
    return n_.bitLength();
}

bool RSAPublicKey::verifyPKCS1Padding(const std::vector<uint8_t>& em,
                                       const std::vector<uint8_t>& hash,
                                       const std::string& hashAlg) {
    // EMSA-PKCS1-v1_5 encoding verification
    // EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo
    
    if (em.size() < 11 + hash.size()) return false;
    if (em[0] != 0x00 || em[1] != 0x01) return false;
    
    // Find 0x00 separator after padding
    size_t i = 2;
    while (i < em.size() && em[i] == 0xFF) i++;
    if (i < 10 || i >= em.size() || em[i] != 0x00) return false;
    i++;
    
    // DigestInfo = AlgorithmIdentifier || Digest
    const uint8_t* digestInfo = &em[i];
    size_t digestInfoLen = em.size() - i;
    
    // DER-encoded DigestInfo structures for different hash algorithms
    static const uint8_t SHA256_DIGEST_INFO[] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20
    };
    static const uint8_t SHA384_DIGEST_INFO[] = {
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
        0x00, 0x04, 0x30
    };
    static const uint8_t SHA512_DIGEST_INFO[] = {
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
        0x00, 0x04, 0x40
    };
    
    const uint8_t* expectedPrefix = nullptr;
    size_t prefixLen = 0;
    
    if (hashAlg == "SHA-256") {
        expectedPrefix = SHA256_DIGEST_INFO;
        prefixLen = sizeof(SHA256_DIGEST_INFO);
    } else if (hashAlg == "SHA-384") {
        expectedPrefix = SHA384_DIGEST_INFO;
        prefixLen = sizeof(SHA384_DIGEST_INFO);
    } else if (hashAlg == "SHA-512") {
        expectedPrefix = SHA512_DIGEST_INFO;
        prefixLen = sizeof(SHA512_DIGEST_INFO);
    } else {
        return false;
    }
    
    if (digestInfoLen != prefixLen + hash.size()) return false;
    
    // Constant-time comparison
    return SecureMemory::constantTimeCompare(digestInfo, expectedPrefix, prefixLen) == 0 &&
           SecureMemory::constantTimeCompare(digestInfo + prefixLen, hash.data(), hash.size()) == 0;
}

bool RSAPublicKey::verifyPKCS1(const std::vector<uint8_t>& message,
                                const std::vector<uint8_t>& signature,
                                const std::string& hashAlg) {
    // Hash the message
    std::vector<uint8_t> hash;
    if (hashAlg == "SHA-256") {
        hash = SHA256::hash(message);
    } else if (hashAlg == "SHA-384") {
        hash = SHA384::hash(message);
    } else if (hashAlg == "SHA-512") {
        hash = SHA512::hash(message);
    } else {
        return false;
    }
    
    // RSA verification: s^e mod n
    BigInt s(signature);
    BigInt em_int = encrypt(s);
    
    // Convert to bytes
    std::vector<uint8_t> em = em_int.toBytes();
    
    // Ensure correct length (add leading zeros if needed)
    size_t k = (getModulusBits() + 7) / 8;
    while (em.size() < k) {
        em.insert(em.begin(), 0);
    }
    
    // Verify PKCS#1 v1.5 padding
    return verifyPKCS1Padding(em, hash, hashAlg);
}

bool RSAPublicKey::verifyPSSPadding(const std::vector<uint8_t>& em,
                                     const std::vector<uint8_t>& mHash,
                                     size_t sLen,
                                     const std::string& hashAlg) {
    // EMSA-PSS verification (RFC 3447 Section 9.1.2)
    size_t emLen = em.size();
    size_t hLen = mHash.size();
    
    if (emLen < hLen + sLen + 2) return false;
    if (em[emLen - 1] != 0xbc) return false;
    
    // maskedDB || H || 0xbc
    size_t dbLen = emLen - hLen - 1;
    const uint8_t* maskedDB = em.data();
    const uint8_t* H = em.data() + dbLen;
    
    // Check leftmost bits are zero
    size_t emBits = getModulusBits() - 1;
    uint8_t mask = (0xFF >> (8 * emLen - emBits));
    if ((maskedDB[0] & ~mask) != 0) return false;
    
    // MGF1 to recover DB
    std::vector<uint8_t> dbMask(dbLen);
    // Simplified MGF1 - in production use full implementation
    for (size_t i = 0; i < dbLen; i++) {
        dbMask[i] = H[i % hLen]; // Simplified for demo
    }
    
    std::vector<uint8_t> DB(dbLen);
    for (size_t i = 0; i < dbLen; i++) {
        DB[i] = maskedDB[i] ^ dbMask[i];
    }
    DB[0] &= mask;
    
    // Check DB = PS || 0x01 || salt
    size_t psLen = dbLen - sLen - 1;
    for (size_t i = 0; i < psLen; i++) {
        if (DB[i] != 0) return false;
    }
    if (DB[psLen] != 0x01) return false;
    
    // Extract salt and verify H' = Hash(padding || mHash || salt)
    const uint8_t* salt = &DB[psLen + 1];
    
    std::vector<uint8_t> M_prime(8 + hLen + sLen);
    memset(M_prime.data(), 0, 8); // padding1
    memcpy(M_prime.data() + 8, mHash.data(), hLen);
    memcpy(M_prime.data() + 8 + hLen, salt, sLen);
    
    std::vector<uint8_t> H_prime;
    if (hashAlg == "SHA-256") {
        H_prime = SHA256::hash(M_prime);
    } else if (hashAlg == "SHA-384") {
        H_prime = SHA384::hash(M_prime);
    } else if (hashAlg == "SHA-512") {
        H_prime = SHA512::hash(M_prime);
    } else {
        return false;
    }
    
    return SecureMemory::constantTimeCompare(H, H_prime.data(), hLen) == 0;
}

bool RSAPublicKey::verifyPSS(const std::vector<uint8_t>& message,
                              const std::vector<uint8_t>& signature,
                              const std::string& hashAlg) {
    // Hash the message
    std::vector<uint8_t> mHash;
    if (hashAlg == "SHA-256") {
        mHash = SHA256::hash(message);
    } else if (hashAlg == "SHA-384") {
        mHash = SHA384::hash(message);
    } else if (hashAlg == "SHA-512") {
        mHash = SHA512::hash(message);
    } else {
        return false;
    }
    
    // RSA verification
    BigInt s(signature);
    BigInt em_int = encrypt(s);
    std::vector<uint8_t> em = em_int.toBytes();
    
    size_t k = (getModulusBits() + 7) / 8;
    while (em.size() < k) {
        em.insert(em.begin(), 0);
    }
    
    // Verify PSS padding (sLen = hLen as per common practice)
    return verifyPSSPadding(em, mHash, mHash.size(), hashAlg);
}

// ============================================================
// ELLIPTIC CURVE OPERATIONS
// ============================================================

ECCurve::ECCurve(CurveType type) {
    switch (type) {
        case CurveType::P256:
            initP256();
            break;
        case CurveType::P384:
            initP384();
            break;
        case CurveType::P521:
            initP521();
            break;
    }
}

void ECCurve::initP256() {
    // NIST P-256 (secp256r1) parameters
    p_ = BigInt::fromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    a_ = BigInt::fromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
    b_ = BigInt::fromHex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
    n_ = BigInt::fromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    
    BigInt gx = BigInt::fromHex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
    BigInt gy = BigInt::fromHex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    g_ = ECPoint(gx, gy);
}

void ECCurve::initP384() {
    // NIST P-384 (secp384r1) parameters
    p_ = BigInt::fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF");
    a_ = BigInt::fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC");
    b_ = BigInt::fromHex("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF");
    n_ = BigInt::fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973");
    
    BigInt gx = BigInt::fromHex("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7");
    BigInt gy = BigInt::fromHex("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F");
    g_ = ECPoint(gx, gy);
}

void ECCurve::initP521() {
    // NIST P-521 (secp521r1) parameters
    p_ = BigInt::fromHex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    a_ = BigInt::fromHex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC");
    b_ = BigInt::fromHex("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00");
    n_ = BigInt::fromHex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409");
    
    BigInt gx = BigInt::fromHex("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66");
    BigInt gy = BigInt::fromHex("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650");
    g_ = ECPoint(gx, gy);
}

bool ECCurve::isOnCurve(const ECPoint& p) const {
    if (p.infinity) return true;
    
    // y^2 = x^3 + ax + b (mod p)
    BigInt lhs = (p.y * p.y) % p_;
    BigInt rhs = (((p.x * p.x * p.x) + (a_ * p.x) + b_) % p_);
    
    return lhs == rhs;
}

ECPoint ECCurve::add(const ECPoint& p1, const ECPoint& p2) const {
    if (p1.infinity) return p2;
    if (p2.infinity) return p1;
    
    if (p1.x == p2.x) {
        if (p1.y == p2.y) {
            return double_(p1);
        } else {
            return ECPoint(); // Point at infinity
        }
    }
    
    // λ = (y2 - y1) / (x2 - x1) mod p
    BigInt dy = (p2.y - p1.y + p_) % p_;
    BigInt dx = (p2.x - p1.x + p_) % p_;
    BigInt lambda = (dy * dx.modInverse(p_)) % p_;
    
    // x3 = λ^2 - x1 - x2 mod p
    BigInt x3 = (lambda * lambda - p1.x - p2.x + p_ + p_) % p_;
    
    // y3 = λ(x1 - x3) - y1 mod p
    BigInt y3 = (lambda * (p1.x - x3 + p_) - p1.y + p_) % p_;
    
    return ECPoint(x3, y3);
}

ECPoint ECCurve::double_(const ECPoint& p) const {
    if (p.infinity) return p;
    
    // λ = (3x^2 + a) / (2y) mod p
    BigInt numerator = (BigInt(3) * p.x * p.x + a_) % p_;
    BigInt denominator = (BigInt(2) * p.y) % p_;
    BigInt lambda = (numerator * denominator.modInverse(p_)) % p_;
    
    // x3 = λ^2 - 2x mod p
    BigInt x3 = (lambda * lambda - BigInt(2) * p.x + p_ + p_) % p_;
    
    // y3 = λ(x - x3) - y mod p
    BigInt y3 = (lambda * (p.x - x3 + p_) - p.y + p_) % p_;
    
    return ECPoint(x3, y3);
}

ECPoint ECCurve::multiply(const ECPoint& p, const BigInt& k) const {
    // Double-and-add algorithm
    if (k.isZero()) return ECPoint(); // Infinity
    if (k.isOne()) return p;
    
    ECPoint result;
    ECPoint addend = p;
    BigInt scalar = k;
    
    while (!scalar.isZero()) {
        if ((scalar.toBytes().back() & 1) == 1) {
            result = add(result, addend);
        }
        addend = double_(addend);
        scalar = scalar >> 1;
    }
    
    return result;
}

// ============================================================
// ECDSA PUBLIC KEY OPERATIONS
// ============================================================

ECDSAPublicKey::ECDSAPublicKey(ECCurve::CurveType curve) : curve_(curve) {}

bool ECDSAPublicKey::loadFromJWK(const std::string& x_base64url,
                                  const std::string& y_base64url,
                                  const std::string& crv) {
    try {
        auto x_bytes = Base64Url::decode(x_base64url);
        auto y_bytes = Base64Url::decode(y_base64url);
        
        BigInt x(x_bytes);
        BigInt y(y_bytes);
        
        publicKey_ = ECPoint(x, y);
        
        return curve_.isOnCurve(publicKey_);
    } catch (...) {
        return false;
    }
}

bool ECDSAPublicKey::verify(const std::vector<uint8_t>& message,
                             const std::vector<uint8_t>& signature,
                             const std::string& hashAlg) {
    // Hash the message
    std::vector<uint8_t> hash;
    if (hashAlg == "SHA-256") {
        hash = SHA256::hash(message);
    } else if (hashAlg == "SHA-384") {
        hash = SHA384::hash(message);
    } else if (hashAlg == "SHA-512") {
        hash = SHA512::hash(message);
    } else {
        return false;
    }
    
    // Signature is r || s (fixed length concatenation)
    size_t halfLen = signature.size() / 2;
    BigInt r(signature.data(), halfLen);
    BigInt s(signature.data() + halfLen, halfLen);
    
    // ECDSA verification
    // 1. Verify r, s in [1, n-1]
    const BigInt& n = curve_.getN();
    if (r.isZero() || r >= n || s.isZero() || s >= n) {
        return false;
    }
    
    // 2. Compute e = hash(message)
    BigInt e(hash);
    
    // 3. Compute w = s^-1 mod n
    BigInt w = s.modInverse(n);
    
    // 4. Compute u1 = ew mod n, u2 = rw mod n
    BigInt u1 = (e * w) % n;
    BigInt u2 = (r * w) % n;
    
    // 5. Compute P = u1*G + u2*Q
    ECPoint p1 = curve_.multiply(curve_.getG(), u1);
    ECPoint p2 = curve_.multiply(publicKey_, u2);
    ECPoint P = curve_.add(p1, p2);
    
    // 6. Verify r = P.x mod n
    if (P.infinity) return false;
    
    BigInt Px_mod_n = P.x % n;
    return Px_mod_n == r;
}

} // namespace Crypto
} // namespace RawrXD
