// retained_proof_abi.cpp — SHA-256 nucleus for MASM retained_proof.asm
#include "../deep2/regenerative/Sha256.hpp"
#include <cstdint>
#include <cstring>

extern "C" {

// RCX=data, RDX=len, R8=out32
void RetainedProof_Sha256Bytes(const void* data, uint64_t len, void* out32) {
    auto h = Deep2::Regenerative::Sha256Bytes(data, static_cast<size_t>(len));
    std::memcpy(out32, h.b, 32);
}

}
