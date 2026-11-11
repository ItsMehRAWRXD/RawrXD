// ============================================================================
// deep2_universal_ingest.cpp  --  RAWRXD_DEEP2_UNIVERSAL_INGEST
// ============================================================================
// Proves Deep2 can ingest EVERY GGUF in the model zoo: parse the header and
// metadata, derive the architecture and config, classify every tensor by name
// into a functional role, build the runtime op graph, and resolve tensor data.
//
// The old path failed closed against one generated per-model IR table. This
// shows the replacement covering the whole zoo, and states plainly which
// architectures can execute a decode graph and which cannot (and why).
//
// Usage: deep2_universal_ingest.exe [--dir F:\OllamaModels\blobs] [--weights]
// ============================================================================
#include <algorithm>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <string>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include "universal_gguf.hpp"

using namespace RawrXD::Deep2::Universal;

static const char* RoleName(Role r) {
    switch (r) {
        case Role::TokenEmbedding: return "embd";
        case Role::OutputNorm: return "out_norm";
        case Role::OutputWeight: return "out_w";
        case Role::AttnNorm: return "attn_norm";
        case Role::AttnQ: return "q";
        case Role::AttnK: return "k";
        case Role::AttnV: return "v";
        case Role::AttnOutput: return "attn_out";
        case Role::AttnQKV: return "qkv(fused)";
        case Role::AttnGate: return "attn_gate";
        case Role::AttnQNorm: return "q_norm";
        case Role::AttnKNorm: return "k_norm";
        case Role::IndexerKProj: return "indexer_k_proj";
        case Role::IndexerKNorm: return "indexer_k_norm";
        case Role::IndexerQProj: return "indexer_q_proj";
        case Role::IndexerQNorm: return "indexer_q_norm";
        case Role::AttnKvAMqa: return "kv_a_mqa";
        case Role::AttnKvB: return "kv_b";
        case Role::FfnNorm: return "ffn_norm";
        case Role::FfnGate: return "gate";
        case Role::FfnUp: return "up";
        case Role::FfnDown: return "down";
        case Role::ExpFfnGate: return "exp_gate";
        case Role::ExpFfnUp: return "exp_up";
        case Role::ExpFfnDown: return "exp_down";
        case Role::RouterGate: return "router";
        case Role::SsmA: return "ssm_a";
        case Role::SsmConv1dW: return "ssm_conv";
        case Role::SsmD: return "ssm_d";
        case Role::SsmIn: return "ssm_in";
        case Role::SsmOut: return "ssm_out";
        case Role::SsmNorm: return "ssm_norm";
        case Role::HyperAttnDown: return "hc_attn_down";
        case Role::HyperAttnInject: return "hc_attn_inject";
        case Role::HyperAttnNorm: return "hc_attn_norm";
        case Role::HyperAttnUp: return "hc_attn_up";
        case Role::HyperFfnDown: return "hc_ffn_down";
        case Role::HyperFfnInject: return "hc_ffn_inject";
        case Role::HyperFfnNorm: return "hc_ffn_norm";
        case Role::HyperFfnUp: return "hc_ffn_up";
        case Role::PleTokenEmbedding: return "ple_token_embd";
        case Role::PleConv: return "ple_conv";
        case Role::PleNorm: return "ple_norm";
        case Role::PleOutput: return "ple_output";
        case Role::RopeFreqs: return "rope";
        case Role::RopeFactors: return "rope_fac";
        default: return "other";
    }
}

int main(int argc, char** argv) {
    std::string dir = "F:\\OllamaModels\\blobs";
    bool weights = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--dir" && i + 1 < argc) dir = argv[++i];
        else if (a == "--weights") weights = true;
        else if (a == "--model" && i + 1 < argc) dir = argv[++i];
    }

    std::vector<std::string> files;
#ifdef _WIN32
    {
        const std::string pattern = dir + "\\*";
        WIN32_FIND_DATAA fd{};
        HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) {
            std::printf("cannot open dir %s\n", dir.c_str());
            return 1;
        }
        do {
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                files.push_back(dir + "\\" + fd.cFileName);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
#else
    if (!std::filesystem::is_directory(dir)) {
        std::printf("cannot open dir %s\n", dir.c_str());
        return 1;
    }
    for (const auto& e : std::filesystem::directory_iterator(dir))
        if (e.is_regular_file()) files.push_back(e.path().string());
#endif
    std::sort(files.begin(), files.end());

    std::printf("=== RAWRXD_DEEP2_UNIVERSAL_INGEST ===\n");
    std::printf("dir=%s  files=%zu  weights=%s\n\n", dir.c_str(), files.size(),
                weights ? "on" : "off");

    // Success criterion: every file that IS a GGUF must ingest. Non-GGUF
    // blobs in an ollama store (manifests, templates, ~35 KB) are EXPECTED to
    // be rejected, and counting them as failures would make a correct run
    // report FAIL.
    auto is_gguf_magic = [](const std::string& path) -> bool {
        FILE* f = std::fopen(path.c_str(), "rb");
        if (!f) return false;
        unsigned char m[4] = {0, 0, 0, 0};
        const size_t n = std::fread(m, 1, 4, f);
        std::fclose(f);
        return n == 4 && m[0] == 0x47 && m[1] == 0x47 && m[2] == 0x55 && m[3] == 0x46;
    };

    size_t gguf_files = 0, gguf_parsed = 0, gguf_failed = 0, non_gguf = 0;
    size_t graph_ok = 0, graph_no = 0;
    std::vector<std::string> archs;
    std::map<uint32_t, size_t> all_types;

    for (const auto& f : files) {
        const bool gguf = is_gguf_magic(f);
        if (!gguf) { ++non_gguf; continue; }
        ++gguf_files;
        const IngestReport& r = Ingest(f, weights);
        const std::string shortName = f.substr(f.size() - 12);
        if (!r.ok) {
            std::printf("PARSE_FAIL  %s  %s\n", shortName.c_str(), r.error.c_str());
            ++gguf_failed;
            continue;
        }
        ++gguf_parsed;
        for (auto& kv : r.type_histogram) all_types[kv.first] += kv.second;

        const ModelSpec& s = r.spec;
        std::printf("OK   %-14s arch=%-13s name=%-40s\n",
                    shortName.c_str(), s.architecture.c_str(), s.model_name.c_str());
        std::printf("     kind=%-18s blocks=%-4llu embd=%-5llu heads=%-4llu kv_heads=%-4llu ffn=%-6llu vocab=%llu\n",
                    ArchKindName(s.kind), (unsigned long long)s.block_count,
                    (unsigned long long)s.embd, (unsigned long long)s.heads,
                    (unsigned long long)s.heads_kv, (unsigned long long)s.ffn,
                    (unsigned long long)s.vocab);
        if (s.expert_count)
            std::printf("     MoE experts=%llu used=%llu shared=%llu expert_ffn=%llu\n",
                        (unsigned long long)s.expert_count, (unsigned long long)s.expert_used,
                        (unsigned long long)s.expert_shared,
                        (unsigned long long)s.expert_ffn);
        if (s.kind == ArchKind::DeepSeekMLA)
            std::printf("     MLA kv_lora=%llu key_len=%llu value_len=%llu leading_dense=%llu\n",
                        (unsigned long long)s.kv_lora_rank, (unsigned long long)s.key_length,
                        (unsigned long long)s.value_length, (unsigned long long)s.leading_dense);
        if (s.kind == ArchKind::Qwen4Exp) {
            std::printf("     Qwen4Exp qsa=%s gdn=%s ple=%s hc=%s sparse_moe=%s "
                        "indexer_heads=%llu indexer_key=%llu top_k=%llu hc_count=%llu hc_rank=%llu\n",
                        s.qwen4exp_has_qsa ? "yes" : "no",
                        s.qwen4exp_has_gdn ? "yes" : "no",
                        s.qwen4exp_has_ple ? "yes" : "no",
                        s.qwen4exp_has_hyperconnection ? "yes" : "no",
                        s.qwen4exp_has_sparse_moe ? "yes" : "no",
                        (unsigned long long)s.indexer_heads,
                        (unsigned long long)s.indexer_key_length,
                        (unsigned long long)s.indexer_top_k,
                        (unsigned long long)s.hyperconnection_count,
                        (unsigned long long)s.hyperconnection_low_rank);
        }

        // Op counts by primitive.
        std::map<Op, size_t> cnt;
        for (const auto& o : r.graph.ops) cnt[o.op]++;
        auto total_ops = r.graph.ops.size();
        bool executable = total_ops > 3 && r.graph.unsupported == 0;
        std::printf("     graph: %zu ops  [embd=1 rms=%zu linear=%zu attn=%zu mla=%zu router=%zu topk=%zu moe=%zu qsa=%zu gdn=%zu ple=%zu hc=%zu sparse_moe=%zu resid=%zu lmhead=1] unsupported=%zu -> %s\n",
                    total_ops, cnt[Op::RmsNorm], cnt[Op::Linear], cnt[Op::Attention],
                    cnt[Op::MlaDecompress], cnt[Op::Router], cnt[Op::TopK], cnt[Op::MoEExecute],
                    cnt[Op::Qsa], cnt[Op::Gdn], cnt[Op::Ple], cnt[Op::Hyperconnection],
                    cnt[Op::SparseMoE], cnt[Op::ResidualAdd], r.graph.unsupported,
                    executable ? "DECODE-GRAPH-EMITTED" : "NO-DECODE-GRAPH");
        if (r.graph.unsupported) graph_no++; else graph_ok++;

        // Role coverage for block 0 (proves classification works per block).
        {
            std::string roles;
            for (const auto& t : r.tensors) {
                if (t.block != 0) continue;
                if (!roles.empty()) roles += " ";
                roles += std::string(RoleName(t.role)) + ":" + t.name.substr(t.name.rfind('.') + 1);
            }
            if (roles.size() > 150) roles = roles.substr(0, 150) + "...";
            std::printf("     blk0 roles: %s\n", roles.c_str());
        }

        // Quantisation coverage.
        std::string q;
        for (auto& kv : r.type_histogram) {
            const ggml_type_traits* tr = ggml_get_type_traits((ggml_type)kv.first);
            if (!q.empty()) q += " ";
            q += std::string(tr ? tr->type_name : "?") + "x" + std::to_string(kv.second);
        }
        std::printf("     types: %s\n", q.c_str());
        std::printf("     tensors=%zu resolved=%zu dequant_ok=%zu no_dequant=%zu gpu_Q4K/Q6K=%zu\n",
                    r.total, r.resolved, r.dequant_capable, r.no_dequant, r.gpu_quant_capable);
        if (!r.unsupported_types.empty()) {
            std::printf("     WARN: ggml cannot dequantise: ");
            for (auto& u : r.unsupported_types) std::printf("%s ", u.c_str());
            std::printf("\n");
        }
        if (weights) {
            size_t n = 0;
            for (auto& kv : r.weights) n += kv.second.size();
            std::printf("     dequantised %zu tensors, %zu floats\n", r.weights.size(), n);
        }
        archs.push_back(s.architecture);
        std::printf("\n");
    }

    std::printf("================ SUMMARY ================\n");
    std::printf("files=%zu  gguf=%zu  non_gguf=%zu\n", files.size(), gguf_files, non_gguf);
    std::printf("gguf_parsed=%zu  gguf_parse_failed=%zu\n", gguf_parsed, gguf_failed);
    std::printf("architectures (%zu distinct):\n", archs.size() - std::distance(archs.begin(), std::unique(archs.begin(), archs.end())));
    std::sort(archs.begin(), archs.end());
    std::vector<std::string> uniq(archs);
    std::sort(uniq.begin(), uniq.end());
    uniq.erase(std::unique(uniq.begin(), uniq.end()), uniq.end());
    for (auto& a : uniq) std::printf("   %s\n", a.c_str());
    std::printf("decode graphs emitted=%zu  architectures-with-no-graph=%zu\n", graph_ok, graph_no);
    std::printf("quantisation types seen across zoo:\n");
    for (auto& kv : all_types) {
        const ggml_type_traits* tr = ggml_get_type_traits((ggml_type)kv.first);
        std::printf("   %-8s x%zu%s\n", tr ? tr->type_name : "?", kv.second,
                    (tr && tr->to_float) ? "  (dequant ok)" : "");
    }
    // PASS means every GGUF in the directory ingested. It does NOT mean every
    // model can execute a decode step: see the graph counts above for that,
    // and each model's own 'NO-DECODE-GRAPH' + unsupported-op reason.
    std::printf("VERDICT=%s\n", (gguf_failed == 0 && gguf_files > 0) ? "PASS" : "FAIL");
    return (gguf_failed == 0 && gguf_files > 0) ? 0 : 1;
}
