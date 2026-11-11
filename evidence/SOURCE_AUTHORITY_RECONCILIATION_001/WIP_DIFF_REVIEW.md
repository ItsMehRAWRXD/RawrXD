# WIP_DIFF_REVIEW

ASOF_UTC=2026-11-02T12:38:40.6858153Z
WIP_DECISION=KEEP_BRANCH
SOURCE_AUTHORITY=a5ae60efecac790598e2e46d9e499eb8ac7287af
COMMIT=0 REVERT=0 STAGE=0 PUSH=0
PROMOTE=0 CERTIFIED=0

## 12 KEEP_BRANCH WIP files (vs HEAD)

### `src/deep2/Deep2Engine.cpp`
SHA256_WORKING=018E49091F34F76ABE542DB3303E86A96960F15E4CBC329AEACA0CBAD5C1FC89
HEAD_BLOB=d77f90ec4c2404fcd6ddf9062fd9df7f933747d5
```
 src/deep2/Deep2Engine.cpp | 2 ++
 1 file changed, 2 insertions(+)
diff --git a/src/deep2/Deep2Engine.cpp b/src/deep2/Deep2Engine.cpp
index d77f90ec4c..3072c63586 100644
--- a/src/deep2/Deep2Engine.cpp
+++ b/src/deep2/Deep2Engine.cpp
@@ -12198,7 +12198,9 @@ void Deep2Engine::enableVulkan(bool enable)
                                 (std::getenv("DEEP2_HYBRID") && std::getenv("DEEP2_HYBRID")[0] == '1');
         const bool wantMulti = snap.plan.openCount >= 1 &&
                                (snap.plan.mode == ExecMode::MultiGpuShard || snap.plan.mode == ExecMode::Hybrid ||
+                                snap.plan.mode == ExecMode::DualSovereign ||
                                 snap.plan.policy == GpuPolicy::Multi || snap.plan.policy == GpuPolicy::Hybrid ||
+                                snap.plan.policy == GpuPolicy::DualLane ||
                                 snap.plan.policy == GpuPolicy::UserList || wantHybrid);
 
         // DualStick stores non-owning VulkanCompute pointers. Clear those
... (truncated if longer; shortstat:  1 file changed, 2 insertions(+))
```

### `src/deep2/K2NativeMoEFfn_ExpertGpuDevice.cpp`
SHA256_WORKING=ADFD6528A500980E32469F5ED249D48CF99F2DA1D6292FB4C839BEC835A0EABB
HEAD_BLOB=25b07198692ab8f27fce1240d4bdd7d671b94f8a
```
 src/deep2/K2NativeMoEFfn_ExpertGpuDevice.cpp | 8 ++++++++
 1 file changed, 8 insertions(+)
diff --git a/src/deep2/K2NativeMoEFfn_ExpertGpuDevice.cpp b/src/deep2/K2NativeMoEFfn_ExpertGpuDevice.cpp
index 25b0719869..dcc04e6029 100644
--- a/src/deep2/K2NativeMoEFfn_ExpertGpuDevice.cpp
+++ b/src/deep2/K2NativeMoEFfn_ExpertGpuDevice.cpp
@@ -215,6 +215,14 @@ bool K2MoEStickEndDevice(unsigned stick, float* hostPartial, size_t H,
     const int ok =
         vc->DownloadBuf(ffn, hostPartial, (uint32_t)H) ? 1 : 0;
     MoeGpuTrace("LIVE_K2_MOE_D2H_DONE stick=%u ok=%d", stick, ok);
+    if (!ok) {
+        std::fprintf(stderr,
+            "[GPU_D2H_FAIL] stick=%u H=%zu lastD2hVk=%llu lastD2hPhase=%s\n",
+            stick, H,
+            (unsigned long long)vc->LastD2hVk(),
+            vc->LastD2hPhase());
+        std::fflush(stderr);
+    }
     ed3::NoteD2h(ok, vc->LastD2hVk(), vc->LastD2hPhase(), hostPartial, H);
     ed3::EmitBoundary(ok ? "END_OK" : "END_FAIL");
     if (!ok) return false;
... (truncated if longer; shortstat:  1 file changed, 8 insertions(+))
```

### `src/deep2/K2NativeMoEFfn_Place.cpp`
SHA256_WORKING=935E1087BFC5A04102DB1F1F36E9F197094E69D167803DB163668DAD69B7D1BA
HEAD_BLOB=97e993741ebf2e60c1d42a410bb279a5e310838f
```
 src/deep2/K2NativeMoEFfn_Place.cpp | 111 +++++++++++++++++++++++++++++++++++++
 1 file changed, 111 insertions(+)
diff --git a/src/deep2/K2NativeMoEFfn_Place.cpp b/src/deep2/K2NativeMoEFfn_Place.cpp
index 97e993741e..024997fb6d 100644
--- a/src/deep2/K2NativeMoEFfn_Place.cpp
+++ b/src/deep2/K2NativeMoEFfn_Place.cpp
@@ -360,6 +360,117 @@ bool K2MoEPlaceAndExec(const GlobalTensorIndex& index, const KimiK2Config& cfg,
             for (size_t i = 0; i < H; ++i) accum[i] += shared[i];
         }
         moe_ltrace::BC(layer, "HOST_MOE_DONE");
+
+        // Layer-1 FFN diagnostic: CPU reference vs native output (host path)
+        std::fprintf(stderr,
+            "[L1_DIAG_PROBE] layer=%u diag_env=%p\n",
+            layer, (const void*)std::getenv("DEEP2_L1_DIAG"));
+        std::fflush(stderr);
+        if (layer == 1 && std::getenv("DEEP2_L1_DIAG"))
+        {
+            const size_t H = cfg.hiddenDim;
+            const size_t I = cfg.moeIntermediateSize ? cfg.moeIntermediateSize : 2048u;
+            std::vector<float> cpuRef(H, 0.0f);
+            auto& reg = QuantKernelRegistry::Instance();
+            auto gemv = [&](int qt, const uint8_t* w, const float* x, float* y,
+                            size_t rows, size_t cols) -> bool {
+                auto k = reg.GetGEMV(qt);
+                if (!k) return false;
+                std::memset(y, 0, rows * sizeof(float));
+                k(w, x, y, rows, cols);
+                return true;
+            };
+            auto siluMul = [](float* gate, const float* up, size_t n) {
+                for (size_t i = 0; i < n; ++i) {
+                    const float g = gate[i];
+                    gate[i] = (g / (1.0f + std::exp(-g))) * up[i];
+                }
+            };
+
+            // CPU reference: shared expert
+            {
+                char gateN[64], upN[64], downN[64];
+                std::snprintf(gateN, sizeof(gateN), "blk.%u.ffn_gate_shexp.weight", layer);
+                std::snprintf(upN, sizeof(upN), "blk.%u.ffn_up_shexp.weight", layer);
+                std::snprintf(downN, sizeof(downN), "blk.%u.ffn_down_shexp.weight", layer);
+
+                WeightSpan gs{}, us{}, dsWt{};
+                std::vector<uint8_t> gBuf, uBuf, dBuf;
+                std::string loadErr;
+                bool ok = ResolveWeight(index, gateN, gs, gBuf, loadErr)
+                       && ResolveWeight(index, upN, us, uBuf, loadErr)
+                       && ResolveWeight(index, downN, dsWt, dBuf, loadErr);
+                if (ok) {
+                    auto gRef = index.Find(gateN);
+                    auto uRef = index.Find(upN);
+                    auto dRef = index.Find(downN);
+                    if (gRef && uRef && dRef) {
+                        const uint8_t* gp = gs.data ? gs.data : gBuf.data();
+                        const uint8_t* up_ = us.data ? us.data : uBuf.data();
+                        const uint8_t* dp = dsWt.data ? dsWt.data : dBuf.data();
+                        std::vector<float> gate(I, 0.0f), up(I, 0.0f);
+                        if (gemv((int)gRef->ggmlType, gp, normed, gate.data(), I, H) &&
+                            gemv((int)uRef->ggmlType, up_, normed, up.data(), I, H)) {
+                            siluMul(gate.data(), up.data(), I);
+                            gemv((int)dRef->ggmlType, dp, gate.data(), cpuRef.data(), H, I);
+                        }
+                    }
+                }
+            }
+
+            // CPU reference: routed experts (weighted)
+            for (uint32_t si = 0; si < route.count; ++si) {
+                int expertId = (int)route.expertIds[si];
+                float weight = route.weights[si];
+                if (expertId < 0) continue;
+
+                char gateN[64], upN[64], downN[64];
+                std::snprintf(gateN, sizeof(gateN), "blk.%u.ffn_gate_exps.weight", layer);
+                std::snprintf(upN, sizeof(upN), "blk.%u.ffn_up_exps.weight", layer);
+                std::snprintf(downN, sizeof(downN), "blk.%u.ffn_down_exps.weight", layer);
+
+                auto gslice = index.FindExpertSlice(gateN, (uint32_t)expertId);
+                auto uslice = index.FindExpertSlice(upN, (uint32_t)expertId);
+                auto dslice = index.FindExpertSlice(downN, (uint32_t)expertId);
... (truncated if longer; shortstat:  1 file changed, 111 insertions(+))
```

### `src/deep2/modelgenie/universal_gguf.cpp`
SHA256_WORKING=0DF84EC39F77A603800F01C0EBE8A8A2FE67A755CF3495CDC17A16186F0E6533
HEAD_BLOB=c27006370a21caa33f4d14668d263e7375318b1d
```
 src/deep2/modelgenie/universal_gguf.cpp | 13 +++++++++++++
 1 file changed, 13 insertions(+)
diff --git a/src/deep2/modelgenie/universal_gguf.cpp b/src/deep2/modelgenie/universal_gguf.cpp
index c27006370a..f220ee7a9f 100644
--- a/src/deep2/modelgenie/universal_gguf.cpp
+++ b/src/deep2/modelgenie/universal_gguf.cpp
@@ -1074,6 +1074,9 @@ OpGraph BuildGraph(const ModelSpec& s, const std::vector<TensorRec>& tensors) {
             // block whose mixer is the Mamba2 scan emitted above, and emitting
             // attention ops with empty weight names there fails at bind time
             // with "linear: no weight".
+            const bool qwen35GatedAttention =
+                s.architecture == "qwen35moe" &&
+                !name(Role::AttnQNorm).empty() && !name(Role::AttnKNorm).empty();
             for (Role r : {Role::AttnQ, Role::AttnK, Role::AttnV}) {
                 GraphOp o;
                 o.op = Op::Linear; o.block = (int32_t)b;
@@ -1085,6 +1088,16 @@ OpGraph BuildGraph(const ModelSpec& s, const std::vector<TensorRec>& tensors) {
                 GraphOp o;
                 o.op = Op::Attention; o.block = (int32_t)b;
                 o.a = "q"; o.b = "k,v"; o.out = "attn_out";
+                if (qwen35GatedAttention) {
+                    // Qwen3.6 attention stores [query, gate] in attn_q and
+                    // applies per-head q/k RMS norms before GQA.  Preserve the
+                    // architecture contract in the graph so OpAttention can
+                    // split the projection instead of treating the 8192-wide
+                    // fused query as 16 heads of width 512.
+                    o.detail = "qwen35_gated_attention;qnorm=" +
+                               name(Role::AttnQNorm) + ";knorm=" +
+                               name(Role::AttnKNorm);
+                }
                 g.ops.push_back(o);
             }
 // Output projection: only for non-MLA models (MLA handles its own output projection)
... (truncated if longer; shortstat:  1 file changed, 13 insertions(+))
```

### `src/deep2/op_gdn.cpp`
SHA256_WORKING=820EDBE7A2D993B1082E31FCF197BA98B839075328AFEBC2D0E1463386E67C84
HEAD_BLOB=cc7f6496d7f0e67d9756cc7fb2bb98c26a431294
```
git : warning: in the working copy of 'src/deep2/op_gdn.cpp', LF will be replaced by CRLF the next time Git touches it
At C:\Users\Garrett\AppData\Local\Temp\ps-script-ed3d087c-cae3-48bb-a713-ede8a8d9a96e.ps1:187 char:6
+   $d=git diff --stat -- $r.path 2>&1 | Out-String
+      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (warning: in the... Git touches it:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
 
 src/deep2/op_gdn.cpp | 139 ++++++++++++++++++++++++++++++++++++++++++++++++++-
 1 file changed, 138 insertions(+), 1 deletion(-)
warning: in the working copy of 'src/deep2/op_gdn.cpp', LF will be replaced by CRLF the next time Git touches it
diff --git a/src/deep2/op_gdn.cpp b/src/deep2/op_gdn.cpp
index cc7f6496d7..311e227fa4 100644
--- a/src/deep2/op_gdn.cpp
+++ b/src/deep2/op_gdn.cpp
@@ -4,6 +4,25 @@
 #include <cmath>
 #include <limits>
 
+namespace {
+
+float GdnSoftplus(float x) {
+    if (x > 20.0f) return x;
+    if (x < -20.0f) return std::exp(x);
+    return std::log1p(std::exp(x));
+}
+
+float GdnSigmoid(float x) {
+    if (x >= 0.0f) {
+        const float e = std::exp(-x);
+        return 1.0f / (1.0f + e);
+    }
+    const float e = std::exp(x);
+    return e / (1.0f + e);
+}
+
+} // namespace
+
 namespace Deep2::Qwen4Exp {
 
 bool ValidateGDNDescriptor(const GDNDescriptor& descriptor,
@@ -77,13 +96,131 @@ bool GDNReferenceStep(const GDNDescriptor& descriptor,
 }
 
 size_t GDNQkvWidth(const GDNDescriptor& d) {
-    return d.key_heads * d.head_dim + d.value_heads * d.head_dim;
+    // Qwen GDN projections are packed as [query | key | value]. The legacy
+    // generic decode below has a separate [key | value] contract and must not
+    // reuse this Qwen-specific width helper.
+    return (static_cast<size_t>(2) * d.key_heads + d.value_heads) *
+           d.head_dim;
 }
 
 size_t GDNOutputWidth(const GDNDescriptor& d) {
     return d.value_heads * d.head_dim;
 }
 
+size_t GDNQwenStateElements(const GDNDescriptor& d) {
+    const uint64_t elements = static_cast<uint64_t>(d.value_heads) *
+                              static_cast<uint64_t>(d.head_dim) *
+                              static_cast<uint64_t>(d.head_dim);
+    if (elements > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) return 0;
+    return static_cast<size_t>(elements);
+}
+
+bool GDNQwenReferenceStep(const GDNDescriptor& descriptor,
+                          const std::vector<float>& mixed_qkv,
+                          const std::vector<float>& beta_logits,
+                          const std::vector<float>& alpha_logits,
+                          const std::vector<float>& a_log,
+                          const std::vector<float>& dt_bias,
+                          const std::vector<float>& norm,
+                          const std::vector<float>& gate,
+                          std::vector<float>& state,
+                          std::vector<float>& output,
+                          std::string& failure) {
+    const size_t Hk = descriptor.key_heads;
+    const size_t Hv = descriptor.value_heads;
+    const size_t D = descriptor.head_dim;
+    if (Hk == 0 || Hv == 0 || D == 0 || Hv % Hk != 0 ||
+        !(descriptor.epsilon > 0.0f) || !std::isfinite(descriptor.epsilon) ||
+        !(descriptor.scale > 0.0f) || !std::isfinite(descriptor.scale)) {
+        failure = "GDN Qwen: invalid head geometry";
+        output.clear();
+        return false;
+    }
+    const size_t qkv_width = (2 * Hk + Hv) * D;
+    const size_t value_width = Hv * D;
+    const size_t expected_state = GDNQwenStateElements(descriptor);
+    if (mixed_qkv.size() != qkv_width || beta_logits.size() != Hv ||
... (truncated if longer; shortstat: warning: in the working copy of 'src/deep2/op_gdn.cpp', LF will be replaced by CRLF the next time Git touches it  1 file changed, 138 insertions(+), 1 deletion(-))
```

### `src/deep2/op_gdn.hpp`
SHA256_WORKING=ABD709BF3613EADBE9925A926E82A84C600D85E57D5F0CDF337A2218D6B14F32
HEAD_BLOB=b2e6542e0f67965c938918264c0f02de5dfbbfbe
```
 src/deep2/op_gdn.hpp | 18 ++++++++++++++++++
 1 file changed, 18 insertions(+)
diff --git a/src/deep2/op_gdn.hpp b/src/deep2/op_gdn.hpp
index b2e6542e0f..66961cfd1b 100644
--- a/src/deep2/op_gdn.hpp
+++ b/src/deep2/op_gdn.hpp
@@ -63,6 +63,24 @@ bool GDNReferenceStep(const GDNDescriptor& descriptor,
 size_t GDNQkvWidth(const GDNDescriptor& d);
 size_t GDNOutputWidth(const GDNDescriptor& d);
 
+// Qwen3.6/Qwen4Exp gated-delta recurrence. This layout is distinct from
+// the generic per-channel GDNReferenceStep contract above: Q/K/V are packed
+// by heads, alpha/beta are per-value-head projections, and the recurrent
+// state is [value_heads, head_dim, head_dim].
+size_t GDNQwenStateElements(const GDNDescriptor& d);
+
+bool GDNQwenReferenceStep(const GDNDescriptor& descriptor,
+                          const std::vector<float>& mixed_qkv,
+                          const std::vector<float>& beta_logits,
+                          const std::vector<float>& alpha_logits,
+                          const std::vector<float>& a_log,
+                          const std::vector<float>& dt_bias,
+                          const std::vector<float>& norm,
+                          const std::vector<float>& gate,
+                          std::vector<float>& state,
+                          std::vector<float>& output,
+                          std::string& failure);
+
 bool GDNReferenceDecode(const GDNDescriptor& descriptor,
                         const std::vector<float>& qkv,
                         const std::vector<float>& beta,
... (truncated if longer; shortstat:  1 file changed, 18 insertions(+))
```

### `src/deep2/runtime_graph_executor.cpp`
SHA256_WORKING=E99E43F59BFC72E0F92B2D526F627D90BB3F5C63C61AD01F27DDA441BB72E4E3
HEAD_BLOB=f7e1f2a3642303c0166ae0302ce72b2eea62ebe7
```
 src/deep2/runtime_graph_executor.cpp | 152 ++++++++++++++++++++++++++++++-----
 1 file changed, 132 insertions(+), 20 deletions(-)
diff --git a/src/deep2/runtime_graph_executor.cpp b/src/deep2/runtime_graph_executor.cpp
index f7e1f2a364..b0a570f020 100644
--- a/src/deep2/runtime_graph_executor.cpp
+++ b/src/deep2/runtime_graph_executor.cpp
@@ -560,9 +560,8 @@ size_t DequantPrefix(const TensorRec& t, std::vector<float>& out, size_t want) {
         return n;
     }
     const ggml_type_traits* tr = ggml_get_type_traits(t.ggml_type);
-    if (!tr || !tr->to_float) return 0;
+    if (!tr || !tr->to_float || tr->blck_size <= 0 || tr->type_size <= 0) return 0;
     const size_t blk = (size_t)tr->blck_size;
-    const size_t row_bytes = (size_t)t.dims.empty() ? 0 : (size_t)t.dims[0];
     const size_t ein = (size_t)t.dims[0];
     const size_t blocks_per_row = (ein + blk - 1) / blk;
     const size_t total_blocks = (size_t)t.bytes / (size_t)tr->type_size;
@@ -570,10 +569,22 @@ size_t DequantPrefix(const TensorRec& t, std::vector<float>& out, size_t want) {
     const size_t n = std::min(want, blocks_per_row * std::max<size_t>(rows, 1) * blk);
 
     out.assign(n, 0.0f);
-    const size_t chunk = 1u << 22;
-    for (size_t off = 0; off < n; off += chunk) {
-        const int cnt = (int)std::min(chunk, n - off);
-        tr->to_float(t.data + off / blk * (size_t)tr->type_size, out.data() + off, cnt);
+    // GGML K-quant dequantizers assert that the requested element count is a
+    // whole block (Q4_K/Q6_K require 256).  Prefix callers legitimately ask
+    // for short vectors such as a 32-element diagnostic or head norm. Decode
+    // complete blocks into a bounded scratch buffer and copy only the requested
+    // prefix, never passing a partial count into the GGML callback.
+    std::vector<float> block(blk, 0.0f);
+    const size_t fullBlocks = n / blk;
+    for (size_t b = 0; b < fullBlocks; ++b) {
+        tr->to_float(t.data + b * (size_t)tr->type_size,
+                    out.data() + b * blk, static_cast<int64_t>(blk));
+    }
+    const size_t tail = n % blk;
+    if (tail > 0) {
+        tr->to_float(t.data + fullBlocks * (size_t)tr->type_size,
+                    block.data(), static_cast<int64_t>(blk));
+        std::copy_n(block.data(), tail, out.data() + fullBlocks * blk);
     }
     return n;
 }
@@ -4472,18 +4483,19 @@ bool Executor::ExecuteToken(uint32_t token, size_t position) {
                 // independent implementation, so this is the last stage in the
                 // block-0 span that can still differ.
                 if (std::getenv("ATTN_TRACE") && in.bName.find("attn_output") != std::string::npos) {
-                    // What row 0 of the weight actually dequantised TO, compared
-                    // against ggml's own dequantize_row_q4_0. The reference value
-                    // for blk.0.attn_output.weight row 0 is
-                    //   0.007111 -0.014224 -0.010668 0 0.010668 0.003556
-                    // NOTE: to_float must be asked for a MULTIPLE of blck_size
-                    // (32 for Q4_0); asking for 8 writes nothing at all, which
-                    // looks like a zero-filled weight and is a probe artefact.
+                    // What row 0 of the weight actually dequantised TO.  GGML's
+                    // Q4_K dequantizer requires a complete 256-element block;
+                    // asking it for a short prefix trips its internal assertion
+                    // and used to make an otherwise valid trace abort the
+                    // process.  Decode one complete block, then print only the
+                    // first values needed by the witness.
                     const TensorRec& wt = tensors_[(size_t)in.b];
-                    std::vector<float> rw0(32, 0.0f);
+                    const size_t traceBlock = std::max<size_t>(
+                        1u, static_cast<size_t>(ggml_blck_size(wt.ggml_type)));
+                    std::vector<float> rw0(traceBlock, 0.0f);
                     const ggml_type_traits* trw = ggml_get_type_traits(wt.ggml_type);
                     if (trw && trw->to_float)
-                        trw->to_float(wt.data, rw0.data(), 32);
+                        trw->to_float(wt.data, rw0.data(), static_cast<int64_t>(traceBlock));
                     std::fprintf(stderr,
                                  "[attnproj-weight0] blk=%d name=%s dims=[%zu,%zu] "
                                  "bytes=%zu data=%p row0: ",
@@ -4811,6 +4823,14 @@ bool Executor::ExecuteToken(uint32_t token, size_t position) {
             case OpKind::LmHead: {
                 std::vector<float> y;
                 std::string e;
+                if (const char* dumpPath = std::getenv("DEEP2_DUMP_FINAL_HIDDEN")) {
+                    if (!hidden_.empty()) {
+                        if (std::FILE* df = std::fopen(dumpPath, "wb")) {
+                            std::fwrite(hidden_.data(), sizeof(float), hidden_.size(), df);
+                            std::fclose(df);
... (truncated if longer; shortstat:  1 file changed, 132 insertions(+), 20 deletions(-))
```

### `src/deep2/vulkan_compute.cpp`
SHA256_WORKING=151908DD533EB245EDD894B65918D871AE832A79148D484EEDDEC7A178277BB6
HEAD_BLOB=a2657a921914490f3e47297475b9b1829f125ade
```
 src/deep2/vulkan_compute.cpp | 234 +++++++++++++++++++++++++++++++++++++++----
 1 file changed, 217 insertions(+), 17 deletions(-)
diff --git a/src/deep2/vulkan_compute.cpp b/src/deep2/vulkan_compute.cpp
index a2657a9219..4cb50e5866 100644
--- a/src/deep2/vulkan_compute.cpp
+++ b/src/deep2/vulkan_compute.cpp
@@ -558,7 +558,25 @@ bool VulkanCompute::createDescriptorSystems() {
     qi.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
     qi.bindingCount = 3;
     qi.pBindings = qb;
-    return vkCreateDescriptorSetLayout(device_, &qi, nullptr, &qSetLayout_) == VK_SUCCESS;
+    if (vkCreateDescriptorSetLayout(device_, &qi, nullptr, &qSetLayout_) != VK_SUCCESS)
+        return false;
+
+    // Qwen GDN uses seven read-only operands, one persistent read/write state
+    // buffer, and one output buffer. Keep this layout distinct from the
+    // four-buffer scalar-op layout so shader binding mistakes fail at pipeline
+    // creation rather than silently corrupting another operator.
+    VkDescriptorSetLayoutBinding gd[9]{};
+    for (uint32_t i = 0; i < 9; ++i) {
+        gd[i].binding = i;
+        gd[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
+        gd[i].descriptorCount = 1;
+        gd[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
+    }
+    VkDescriptorSetLayoutCreateInfo gi{};
+    gi.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
+    gi.bindingCount = 9;
+    gi.pBindings = gd;
+    return vkCreateDescriptorSetLayout(device_, &gi, nullptr, &gdnSetLayout_) == VK_SUCCESS;
 }
 
 std::string VulkanCompute::shaderPath(const char* file) const {
@@ -649,9 +667,10 @@ bool VulkanCompute::createPipelines() {
     const std::string so = shaderPath("deep2_spec_ops.spv");
     const std::string sa = shaderPath("deep2_spec_attn.spv");
     const std::string ac = shaderPath("deep2_spec_accept.spv");
+    const std::string gd = shaderPath("deep2_qwen4exp_gdn.spv");
 
     std::fprintf(stderr,
-        "[SHADER_PATH] ops=%s q=%s qb=%s q4r=%s q8r=%s qn=%s am=%s so=%s sa=%s ac=%s\n",
+        "[SHADER_PATH] ops=%s q=%s qb=%s q4r=%s q8r=%s qn=%s am=%s so=%s sa=%s ac=%s gd=%s\n",
         ops.empty()?"NOTFOUND":ops.c_str(),
         q.empty()?"NOTFOUND":q.c_str(),
         qb.empty()?"NOTFOUND":qb.c_str(),
@@ -661,7 +680,8 @@ bool VulkanCompute::createPipelines() {
         am.empty()?"NOTFOUND":am.c_str(),
         so.empty()?"NOTFOUND":so.c_str(),
         sa.empty()?"NOTFOUND":sa.c_str(),
-        ac.empty()?"NOTFOUND":ac.c_str());
+        ac.empty()?"NOTFOUND":ac.c_str(),
+        gd.empty()?"NOTFOUND":gd.c_str());
     std::fflush(stderr);
 
     bool okOps=false, okQ=false, okQb=false, okQ4r=false, okQ8r=false, okQn=false;
@@ -699,10 +719,16 @@ bool VulkanCompute::createPipelines() {
         (void)createPipelineFromFile(
             sa,opsSetLayout_,sizeof(SpecAttnPush),
             specAttnPipelineLayout_,specAttnPipeline_);
+    if (!gd.empty())
+        (void)createPipelineFromFile(
+            gd, gdnSetLayout_, sizeof(GdnPush),
+            gdnPipelineLayout_, gdnPipeline_);
 
     std::fprintf(stderr,
-        "[PIPELINE_CREATE] ops=%u q=%u qb=%u q4r=%u q8r=%u qn=%u\n",
-        okOps?1u:0u, okQ?1u:0u, okQb?1u:0u, okQ4r?1u:0u, okQ8r?1u:0u, okQn?1u:0u);
+        "[PIPELINE_CREATE] ops=%u q=%u qb=%u q4r=%u q8r=%u qn=%u gdn=%u\n",
+        okOps?1u:0u, okQ?1u:0u, okQb?1u:0u, okQ4r?1u:0u,
+        okQ8r?1u:0u, okQn?1u:0u,
+        gdnPipeline_ != VK_NULL_HANDLE ? 1u : 0u);
     std::fflush(stderr);
 
     return opsPipeline_ != VK_NULL_HANDLE;
@@ -3706,9 +3732,11 @@ void VulkanCompute::ResetMLACache() {
 }
 
 void VulkanCompute::ResetGdnState(uint64_t stateKey) {
-    // Stub: clear per-block GDN device state keyed by stateKey.
-    // Future hooks for clearing pipeline state caches can be added here.
-    (void)stateKey;
+    std::lock_guard<std::recursive_mutex> lock(apiMu_);
... (truncated if longer; shortstat:  1 file changed, 217 insertions(+), 17 deletions(-))
```

### `src/deep2/vulkan_compute.h`
SHA256_WORKING=FF642B664444190042CE3C8FBAB3D1310B1F0AC39C64E16668B29943962FB597
HEAD_BLOB=11b6b822b435a4117b0f4045c414e1cf6a30b3d5
```
 src/deep2/vulkan_compute.h | 25 +++++++++++++++++++++++--
 1 file changed, 23 insertions(+), 2 deletions(-)
diff --git a/src/deep2/vulkan_compute.h b/src/deep2/vulkan_compute.h
index 11b6b822b4..b6e1e8d7da 100644
--- a/src/deep2/vulkan_compute.h
+++ b/src/deep2/vulkan_compute.h
@@ -529,8 +529,9 @@ public:
     // leaking into a newly bound model.
     void ResetGdnState(uint64_t stateKey);
 
-    // GDN dispatch: Qwen3.5/Qwen4Exp gated delta-net device kernel. Stubbed
-    // to CPU fallback until a matching Vulkan stateful kernel is wired.
+    // GDN dispatch: Qwen3.5/Qwen4Exp gated delta-net device kernel. The
+    // recurrent state is retained by stateKey across token dispatches and is
+    // discarded by ResetGdnState at executor/model-session boundaries.
     bool DispatchGdn(const float* mixed, size_t mixedSize,
                      const float* beta, size_t betaSize,
                      const float* alpha, size_t alphaSize,
@@ -542,6 +543,18 @@ public:
                      float epsilon, float scale, bool gateSigmoid,
                      uint64_t stateKey, std::vector<float>& output);
 
+    struct GdnPush {
+        uint32_t tokens = 1;
+        uint32_t keyHeads = 0;
+        uint32_t valueHeads = 0;
+        uint32_t headDim = 0;
+        float epsilon = 0.0f;
+        float scale = 1.0f;
+        uint32_t gateSigmoid = 0;
+        uint32_t reserved = 0;
+    };
+    static_assert(sizeof(GdnPush) == 32, "GDN push constants must match GLSL");
+
     // ========== Download ticket ==========
     struct DownloadTicket {
         DeviceBuf staging{};
@@ -1490,9 +1503,12 @@ private:
     VkPipelineLayout opsPipelineLayout_ = VK_NULL_HANDLE;
     VkPipelineLayout qPipelineLayout_ = VK_NULL_HANDLE;
     VkPipelineLayout qNvfp4PipelineLayout_ = VK_NULL_HANDLE;
+    VkDescriptorSetLayout gdnSetLayout_ = VK_NULL_HANDLE;
+    VkPipelineLayout gdnPipelineLayout_ = VK_NULL_HANDLE;
     VkPipeline opsPipeline_ = VK_NULL_HANDLE;
     VkPipeline qPipeline_ = VK_NULL_HANDLE;
     VkPipeline qNvfp4Pipeline_ = VK_NULL_HANDLE;
+    VkPipeline gdnPipeline_ = VK_NULL_HANDLE;
 
     bool calibratedAvailable_ = false;
     VkTimeDomainEXT hostTimeDomain_ = VK_TIME_DOMAIN_DEVICE_EXT;
@@ -1610,6 +1626,11 @@ private:
     uint32_t mlaCacheCapacity_ = 0;
     uint32_t mlaCacheMaxSeq_ = 0;
 
+    // Stateful Qwen GDN device buffers. Entries are keyed by the executor
+    // owner/block identity supplied by RuntimeGraphExecutor. A state buffer
+    // is never reused across a geometry change or an explicit reset.
+    std::unordered_map<uint64_t, DeviceBuf> gdnStates_;
+
     uint64_t gemvSuccess_ = 0;
     uint64_t weightUploads_ = 0;
     uint64_t weightHits_ = 0;
... (truncated if longer; shortstat:  1 file changed, 23 insertions(+), 2 deletions(-))
```

### `src/win32app/Win32IDE_GhostText.cpp`
SHA256_WORKING=9014B4E1E823151E7670795571AD9A8659AA5D54F549FBF532BF0DD74EC73AEB
HEAD_BLOB=9ef6ad0bcb1bf4298526e4729c67cb49cc025d5e
```
git : warning: in the working copy of 'src/win32app/Win32IDE_GhostText.cpp', LF will be replaced by CRLF the next time 
Git touches it
At C:\Users\Garrett\AppData\Local\Temp\ps-script-ed3d087c-cae3-48bb-a713-ede8a8d9a96e.ps1:187 char:6
+   $d=git diff --stat -- $r.path 2>&1 | Out-String
+      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (warning: in the... Git touches it:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
 
 src/win32app/Win32IDE_GhostText.cpp | 103 ++++++++++++++++++++++++++++++++----
 1 file changed, 94 insertions(+), 9 deletions(-)
warning: in the working copy of 'src/win32app/Win32IDE_GhostText.cpp', LF will be replaced by CRLF the next time Git touches it
diff --git a/src/win32app/Win32IDE_GhostText.cpp b/src/win32app/Win32IDE_GhostText.cpp
index 9ef6ad0bcb..42682bc521 100644
--- a/src/win32app/Win32IDE_GhostText.cpp
+++ b/src/win32app/Win32IDE_GhostText.cpp
@@ -2,7 +2,11 @@
 
 #include <richedit.h>
 #include <algorithm>
+#include <atomic>
+#include <chrono>
+#include <cstdlib>
 #include <memory>
+#include <thread>
 #include <utility>
 
 namespace {
@@ -11,22 +15,40 @@ constexpr UINT kGhostResult = WM_APP + 73;
 struct Result {
     NativeGhostTextController* owner;
     std::shared_ptr<void> requestIdentity;
+    uint64_t requestId;
     uint64_t generation;
     std::string text;
     bool success;
 };
+std::atomic<uint64_t> g_nextGhostRequestId{1};
+
+// Candidate-only deterministic scheduling control.  It is disabled unless
+// explicitly enabled by both delay variables.  Production runs therefore
+// retain the provider's normal callback timing and behavior.
+void applyGhostTextTestDelay(uint64_t requestId) {
+    const char* first = std::getenv("RAWRXD_GHOSTTEXT_TEST_DELAY_A_MS");
+    const char* second = std::getenv("RAWRXD_GHOSTTEXT_TEST_DELAY_B_MS");
+    if (!first || !second) return;
+    const char* selected = requestId == 1 ? first : (requestId == 2 ? second : nullptr);
+    if (!selected || !*selected) return;
+    char* end = nullptr;
+    const long delayMs = std::strtol(selected, &end, 10);
+    if (end == selected || *end != '\0' || delayMs <= 0 || delayMs > 30000) return;
+    std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
+}
 }
 
 NativeGhostTextController::~NativeGhostTextController() { detach(); }
 
 bool NativeGhostTextController::attach(HWND host, HWND editor, Request request,
-                                       std::string promptPrefix) {
+                                       std::string promptPrefix, Trace trace) {
     if (!host || !editor || !request) return false;
     detach();
     m_host = host;
     m_editor = editor;
     m_request = std::move(request);
     m_promptPrefix = std::move(promptPrefix);
+    m_trace = std::move(trace);
     m_requestIdentity = std::make_shared<int>(0);
     SetPropA(m_editor, "RawrXD.GhostText", this);
     m_originalProc = reinterpret_cast<WNDPROC>(SetWindowLongPtrA(
@@ -50,6 +72,7 @@ void NativeGhostTextController::detach() {
     m_hint = nullptr; m_editor = nullptr; m_host = nullptr; m_originalProc = nullptr;
     m_timer = 0; m_completion.clear(); m_snapshot.clear(); m_promptPrefix.clear();
     m_requestIdentity.reset();
+    m_trace = {};
     m_requestPending = false;
     ++m_generation;
 }
@@ -80,6 +103,7 @@ void NativeGhostTextController::triggerCompletion() {
 
 void NativeGhostTextController::requestCompletion() {
     if (!m_request || m_snapshot.empty()) return;
+    const uint64_t requestId = g_nextGhostRequestId.fetch_add(1);
     const uint64_t generation = m_generation;
     const std::weak_ptr<void> requestIdentity = m_requestIdentity;
     const HWND host = m_host;
@@ -89,18 +113,26 @@ void NativeGhostTextController::requestCompletion() {
         : m_promptPrefix + "\n") + m_snapshot;
     auto accumulated = std::make_shared<std::string>();
     m_requestPending = true;
-    m_request(prompt, [owner, host, requestIdentity, generation, accumulated](
... (truncated if longer; shortstat: warning: in the working copy of 'src/win32app/Win32IDE_GhostText.cpp', LF will be replaced by CRLF the next time Git touches it  1 file changed, 94 insertions(+), 9 deletions(-))
```

### `src/win32app/Win32IDE_GhostText.h`
SHA256_WORKING=361644E413147800328F00B652F87EE474783E714ABD3C8811EC72CBE66FA17A
HEAD_BLOB=84fd4ee49c795277a763deaf21501214c3dc9f82
```
git : warning: in the working copy of 'src/win32app/Win32IDE_GhostText.h', LF will be replaced by CRLF the next time 
Git touches it
At C:\Users\Garrett\AppData\Local\Temp\ps-script-ed3d087c-cae3-48bb-a713-ede8a8d9a96e.ps1:187 char:6
+   $d=git diff --stat -- $r.path 2>&1 | Out-String
+      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (warning: in the... Git touches it:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
 
 src/win32app/Win32IDE_GhostText.h | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)
warning: in the working copy of 'src/win32app/Win32IDE_GhostText.h', LF will be replaced by CRLF the next time Git touches it
diff --git a/src/win32app/Win32IDE_GhostText.h b/src/win32app/Win32IDE_GhostText.h
index 84fd4ee49c..5aec5a9ef7 100644
--- a/src/win32app/Win32IDE_GhostText.h
+++ b/src/win32app/Win32IDE_GhostText.h
@@ -10,12 +10,13 @@ class NativeGhostTextController {
 public:
     using Request = std::function<void(const std::string&,
         std::function<void(const std::string&, bool, bool)>)>;
+    using Trace = std::function<void(const std::string&)>;
 
     NativeGhostTextController() = default;
     ~NativeGhostTextController();
 
     bool attach(HWND host, HWND editor, Request request,
-                std::string promptPrefix = {});
+                std::string promptPrefix = {}, Trace trace = {});
     void detach();
     void onEditorChanged();
     // Start a completion explicitly from the editor (Ctrl+Space).  Normal
@@ -42,12 +43,14 @@ private:
     HWND m_hint = nullptr;
     WNDPROC m_originalProc = nullptr;
     Request m_request;
+    Trace m_trace;
     std::string m_promptPrefix;
     std::string m_completion;
     std::string m_snapshot;
     uint64_t m_generation = 0;
     UINT_PTR m_timer = 0;
     bool m_requestPending = false;
+    uint64_t m_requestId = 0;
     // A per-attachment identity fences callbacks that outlive a controller
     // detach/rebind. Stale completions are discarded without dereferencing
     // the old object.
... (truncated if longer; shortstat: warning: in the working copy of 'src/win32app/Win32IDE_GhostText.h', LF will be replaced by CRLF the next time Git touches it  1 file changed, 4 insertions(+), 1 deletion(-))
```

### `src/win32app/Win32IDE_GhostTextIntegration.cpp`
SHA256_WORKING=AC36A5109761A4FA1B2F96DC27699559F88C1C4AF9E58DA35CB719CFEF5CA2EC
HEAD_BLOB=431b4926aa80adc37a695326d9dccd2be3379b29
```
git : warning: in the working copy of 'src/win32app/Win32IDE_GhostTextIntegration.cpp', LF will be replaced by CRLF 
the next time Git touches it
At C:\Users\Garrett\AppData\Local\Temp\ps-script-ed3d087c-cae3-48bb-a713-ede8a8d9a96e.ps1:187 char:6
+   $d=git diff --stat -- $r.path 2>&1 | Out-String
+      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (warning: in the... Git touches it:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
 
 src/win32app/Win32IDE_GhostTextIntegration.cpp | 48 ++++++++++++++++++++++++--
 1 file changed, 46 insertions(+), 2 deletions(-)
warning: in the working copy of 'src/win32app/Win32IDE_GhostTextIntegration.cpp', LF will be replaced by CRLF the next time Git touches it
diff --git a/src/win32app/Win32IDE_GhostTextIntegration.cpp b/src/win32app/Win32IDE_GhostTextIntegration.cpp
index 431b4926aa..4923d425e5 100644
--- a/src/win32app/Win32IDE_GhostTextIntegration.cpp
+++ b/src/win32app/Win32IDE_GhostTextIntegration.cpp
@@ -1,5 +1,6 @@
 #include "Win32IDE.h"
 #include <richedit.h>
+#include "../backend/ollama_client.h"
 
 void Win32IDE::initializeNativeGhostText() {
     if (!m_hwndMain || !m_hwndEditor) return;
@@ -76,7 +77,13 @@ void Win32IDE::initializeNativeGhostText() {
     if (!m_ghostText) m_ghostText = std::make_unique<NativeGhostTextController>();
     const bool attached = m_ghostText->attach(
         m_hwndMain, m_hwndEditor, request,
-        "Complete the following code. Return only the completion text, no markdown:");
+        "Complete the following code. Return only the completion text, no markdown:",
+        [this](const std::string& event) {
+            // Controller traces are emitted only from the UI message/timer
+            // path; keeping this sink on the UI thread avoids racing the
+            // native output controls while preserving raw lifecycle evidence.
+            appendNativeDebugOutput("[GhostText] " + event + "\n");
+        });
     appendNativeDebugOutput(std::string("[GhostText] native controller ") +
                             (attached ? "READY\n" : "FAILED\n"), !attached);
 
@@ -113,7 +120,10 @@ void Win32IDE::initializeNativeGhostText() {
     for (const auto& surface : surfaces) {
         if (!surface.hwnd || surface.hwnd == m_hwndEditor) continue;
         auto controller = std::make_unique<NativeGhostTextController>();
-        if (controller->attach(m_hwndMain, surface.hwnd, request, surface.prompt)) {
+        if (controller->attach(m_hwndMain, surface.hwnd, request, surface.prompt,
+                               [this](const std::string& event) {
+                                   appendNativeDebugOutput("[GhostText] " + event + "\n");
+                               })) {
             m_ghostTextInputs.push_back(std::move(controller));
         }
     }
@@ -174,6 +184,40 @@ void Win32IDE::requestNativeGhostText(
     const std::string& prompt,
     std::function<void(const std::string&, bool, bool)> callback)
 {
+    // GhostText requests are independently fenced by the controller. Allow a
+    // newer request to run while an older one is still in flight; the older
+    // response is discarded by generation/identity checks on the UI thread.
+    const ChatModelEntry ghostRoute =
+        std::exchange(m_pendingInferenceModel, ChatModelEntry{});
+    if (ghostRoute.source == ChatModelEntry::Source::Ollama &&
+        !ghostRoute.identifier.empty()) {
+        const std::string baseUrl = m_ollamaBaseUrl;
+        const int maxTokens = effectiveMaxTokensForPrompt(prompt);
+        const int contextTokens = m_currentContextTokens;
+        const ReasoningMode reasoningMode = m_reasoningMode;
+        std::thread([baseUrl, model = ghostRoute.identifier, prompt,
+                     maxTokens, contextTokens, reasoningMode,
+                     callback = std::move(callback)]() mutable {
+            try {
+                (void)reasoningMode;
+                RawrXD::Backend::OllamaGenerateRequest request;
+                request.model = model;
+                request.prompt = prompt;
+                request.stream = false;
+                request.options["num_predict"] = std::to_string(maxTokens);
+                request.options["num_ctx"] = std::to_string(contextTokens);
+                RawrXD::Backend::OllamaClient client(baseUrl);
+                client.setTimeoutSeconds(120);
+                const RawrXD::Backend::OllamaResponse result = client.generateSync(request);
+                const std::string response = result.response.empty()
+                    ? result.message : result.response;
+                if (callback) callback(response, true, !response.empty());
+            } catch (...) {
+                if (callback) callback("", true, false);
+            }
+        }).detach();
+        return;
+    }
     generateResponseAsync(prompt, std::move(callback));
 }
 
... (truncated if longer; shortstat: warning: in the working copy of 'src/win32app/Win32IDE_GhostTextIntegration.cpp', LF will be replaced by CRLF the next time Git touches it  1 file changed, 46 insertions(+), 2 deletions(-))
```

## TOOL_NOT_PRODUCT (excluded from product cert)
- `tools/deep2_gpu_certify.cpp`
- `tools/deep2_qwen4exp_gdn_probe.cpp`
- `tools/deep2_qwen4exp_pipeline_probe.cpp`
- `tools/deep2_vulkan_gdn_dispatch_probe.cpp`

## QUARANTINE_LOGICAL (20)
- `src/deep2/shaders/deep2_qgemv.spv` | ??
- `src/deep2/shaders/deep2_qwen4exp_gdn.spv` | ??
- `src/deep2/shaders/deep2_qwen4exp_hc_combine.spv` | ??
- `src/deep2/shaders/deep2_qwen4exp_moe_router.spv` | ??
- `src/deep2/shaders/deep2_qwen4exp_ple.spv` | ??
- `src/deep2/shaders/deep2_qwen4exp_qsa_score.spv` | ??
- `tools/llama_dump_logits_teacher_forced.cpp` | M
- `tools/qwen36_gdn_cpu_parity.py` | ??
- `tools/shaders/quant_attn_decode.comp` | ??
- `tools/shaders/quant_attn_decode.spv` | ??
- `tools/shaders/quant_dot_row4_q2k_specialized.spv` | ??
- `tools/shaders/quant_dot_row4_q3k_specialized.spv` | ??
- `tools/shaders/quant_dot_row4_q4k_specialized.spv` | ??
- `tools/shaders/quant_dot_row4_q5k_specialized.spv` | ??
- `tools/shaders/quant_dot_row4_q6k_specialized.spv` | ??
- `tools/shaders/quant_dot_row8_q2k_specialized.spv` | ??
- `tools/shaders/quant_dot_row8_q3k_specialized.spv` | ??
- `tools/shaders/quant_dot_row8_q4k_specialized.spv` | ??
- `tools/shaders/quant_dot_row8_q5k_specialized.spv` | ??
- `tools/shaders/quant_dot_row8_q6k_specialized.spv` | ??
