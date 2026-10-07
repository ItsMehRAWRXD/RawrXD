#pragma once
// Deep2CertBridge.hpp
// Drop this next to Deep2Engine.cpp and include it only in certification builds.
// No external dependencies. It does not alter inference unless you call the hooks.

#include "Deep2CorrectnessCert.hpp"

namespace deep2cert_bridge {

inline deep2cert::Recorder& recorder() {
    static deep2cert::Recorder r(stderr, 1.0e6);
    return r;
}

inline void stage(const char* name, const float* p, std::size_t n) {
    recorder().capture(name, p, n);
}

inline bool parity(const char* name,
                   const float* actual,
                   const float* reference,
                   std::size_t n,
                   double atol = 1e-5,
                   double rtol = 1e-4) {
    return recorder().parity(name, actual, reference, n, atol, rtol);
}

inline bool failed() {
    return recorder().failed();
}

} // namespace deep2cert_bridge

// Suggested exact boundaries in Deep2Engine forward path:
//
// deep2cert_bridge::stage("L00_RESIDUAL_IN", residual, hiddenDim);
// deep2cert_bridge::stage("L00_ATTN_NORM", normed, hiddenDim);
// deep2cert_bridge::stage("L00_Q_PRE_ROPE", q, numHeads * headDim);
// deep2cert_bridge::stage("L00_K_PRE_ROPE", k, numKVHeads * headDim);
// deep2cert_bridge::stage("L00_V", v, numKVHeads * headDim);
// deep2cert_bridge::stage("L00_Q_POST_ROPE", q, numHeads * headDim);
// deep2cert_bridge::stage("L00_K_POST_ROPE", k, numKVHeads * headDim);
// deep2cert_bridge::stage("L00_ATTN_OUT", attnOut, numHeads * headDim); // BEFORE O projection
// deep2cert_bridge::stage("L00_ATTN_O", projected, hiddenDim);          // AFTER O projection
// deep2cert_bridge::stage("L00_RESIDUAL_ATTN", residual, hiddenDim);
// deep2cert_bridge::stage("L00_FFN_NORM", ffnNorm, hiddenDim);
// deep2cert_bridge::stage("L00_FFN_GATE", gate, intermediateDim);
// deep2cert_bridge::stage("L00_FFN_UP", up, intermediateDim);
// deep2cert_bridge::stage("L00_FFN_ACT", act, intermediateDim);
// deep2cert_bridge::stage("L00_FFN_DOWN", down, hiddenDim);
// deep2cert_bridge::stage("L00_RESIDUAL_OUT", residual, hiddenDim);
//
// To isolate an O-projection failure:
//   std::vector<float> o_ref(hiddenDim);
//   deep2cert::gemv_q4_0_f32(
//       reinterpret_cast<const deep2cert::block_q4_0*>(attnOutputWeightRaw),
//       attnOut, o_ref.data(), hiddenDim, numHeads * headDim);
//   deep2cert_bridge::parity("L00_O_PROJ_Q4_0", projected, o_ref.data(), hiddenDim, 2e-4, 2e-3);
//
// IMPORTANT: matrix orientation above assumes weights are [rows=output, cols=input].
// If your GGUF tensor is presented transposed, do not "fix" the reference. Fix the engine's
// tensor orientation/stride so its logical operation matches y = W*x.
