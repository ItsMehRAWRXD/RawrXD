#include "ModelGenomeReader.hpp"
#include "QuantParityRegistry.h"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <string>

namespace MG = RawrXD::Deep2::ModelGenie;
using Registry = RawrXD::Deep2::QuantParityRegistry;

static int checks = 0;
static int failures = 0;

static void Check(bool condition, const char* name) {
    ++checks;
    if (!condition) ++failures;
    std::printf("%s %s\n", condition ? "PASS" : "FAIL", name);
}

static MG::ModelGenome Graph(std::initializer_list<MG::Primitive> primitives) {
    MG::ModelGenome genome;
    for (auto primitive : primitives) {
        MG::OperationIR op;
        op.requiredPrimitive = primitive;
        genome.executionOps.push_back(op);
    }
    return genome;
}

static bool Contains(const std::vector<MG::Primitive>& values, MG::Primitive p) {
    return std::find(values.begin(), values.end(), p) != values.end();
}

static bool Partitioned(const MG::CapabilityManifest& caps) {
    if (caps.availablePrimitives.size() + caps.unimplementedPrimitives.size() !=
        caps.requiredPrimitives.size()) return false;
    for (auto p : caps.requiredPrimitives) {
        if (Contains(caps.availablePrimitives, p) == Contains(caps.unimplementedPrimitives, p))
            return false;
    }
    return true;
}

static bool WriteFixture(const std::filesystem::path& root) {
    std::filesystem::create_directories(root / "genie_out");
    std::ofstream genome(root / "genie_out/model.genome.txt");
    genome << "architecture deepseek2\nmodel_name synthetic_binding_fixture\n"
              "block_count 1\nleading_dense_blocks 1\nembedding_length 4\n"
              "feed_forward_length 4\ncontext_length 16\nvocab_size 4\n"
              "head_count 1\nhead_count_kv 1\nrope_freq_base 10000\n"
              "rope_dimension_count 2\nrms_eps 0.00001\nkv_lora_rank 2\n"
              "key_length 4\nvalue_length 4\nencoded_weight_bytes 832\n";
    std::ofstream physical(root / "genie_out/model.physical.txt");
    physical << "data_start 0\nfile_bytes 832\ngguf_version 3\ntensor_count 13\nalignment 32\n";
    const char* names[] = {
        "token_embd.weight", "output_norm.weight", "output.weight",
        "blk.0.attn_norm.weight", "blk.0.attn_q.weight",
        "blk.0.attn_kv_a_norm.weight", "blk.0.attn_kv_a_mqa.weight",
        "blk.0.attn_kv_b.weight", "blk.0.attn_output.weight",
        "blk.0.ffn_norm.weight", "blk.0.ffn_down.weight",
        "blk.0.ffn_gate.weight", "blk.0.ffn_up.weight"
    };
    size_t offset = 0;
    for (const auto* name : names) {
        physical << name << " f32 [4,4] 64 " << offset << '\n';
        offset += 64;
    }
    std::ofstream execution(root / "genie_out/model.execution.txt");
    execution << "FIRST_UNPROVEN_BOUNDARY MLA_DECOMPRESS_FORWARD\n"
                 "WHY_UNPROVEN historical diagnostic, not a current binding verdict\n";
    return genome.good() && physical.good() && execution.good();
}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: modelgenome_capabilities_tests <fixture-output-directory>\n");
        return 2;
    }
    using P = MG::Primitive;

    auto implemented = Graph({P::RmsNormFwd, P::LinearFwd, P::AttentionFwd,
        P::MlaDecompressFwd, P::RouterFwd, P::TopKFwd, P::MoEExecuteFwd,
        P::ResidualAddFwd, P::LMHeadFwd});
    // Reproduce the stale reader's contradictory input state.
    implemented.capabilities.availablePrimitives = {P::MatMulFwd};
    implemented.capabilities.unimplementedPrimitives = {P::MlaDecompressFwd};
    implemented.capabilities.firstUnimplementedPrimitive = P::MlaDecompressFwd;
    MG::RefreshModelGenomeCapabilities(implemented);
    Check(implemented.capabilities.availablePrimitives.size() == 9,
          "all nine audited implemented registry bindings are available");
    Check(implemented.capabilities.unimplementedPrimitives.empty() &&
          implemented.capabilities.firstUnimplementedPrimitive == P::None,
          "stale MLA boundary and unavailable claims cleared");
    Check(Partitioned(implemented.capabilities), "implemented manifest partitions required set");
    Check(implemented.capabilities.runtimeExecutable && Registry::RuntimeExecutable(implemented),
          "complete primitive bindings permit binding-level execution");

    auto unsupported = Graph({P::LinearFwd, P::MatMulFwd, P::LMHeadFwd, P::MatMulFwd});
    MG::RefreshModelGenomeCapabilities(unsupported);
    Check(unsupported.capabilities.requiredPrimitives ==
              std::vector<P>{P::LinearFwd, P::MatMulFwd, P::LMHeadFwd},
          "required primitives preserve first occurrence and remove duplicates");
    Check(!Contains(unsupported.capabilities.availablePrimitives, P::MatMulFwd) &&
          Contains(unsupported.capabilities.unimplementedPrimitives, P::MatMulFwd),
          "required MatMul remains unavailable");
    Check(Partitioned(unsupported.capabilities), "unsupported manifest partitions required set");
    Check(!unsupported.capabilities.runtimeExecutable && !Registry::RuntimeExecutable(unsupported),
          "required MatMul fails admission");

    auto unknown = Graph({P::LinearFwd, static_cast<P>(0xffff)});
    MG::RefreshModelGenomeCapabilities(unknown);
    Check(unknown.capabilities.unimplementedPrimitives == std::vector<P>{static_cast<P>(0xffff)},
          "unknown required primitive explicitly retained as missing");
    Check(!unknown.capabilities.runtimeExecutable && !Registry::RuntimeExecutable(unknown),
          "unknown required primitive fails admission");

    auto empty = Graph({});
    MG::RefreshModelGenomeCapabilities(empty);
    Check(!empty.capabilities.runtimeExecutable, "empty produced graph is not executable");

    const std::filesystem::path fixture(argv[1]);
    Check(WriteFixture(fixture), "frozen fixture written");
    MG::ModelGenome loaded;
    const bool loadedOk = MG::LoadModelGenomeFromEvidence(fixture.generic_string(), loaded);
    Check(loadedOk, "actual frozen reader produces MLA graph");
    Check(loadedOk && Contains(loaded.capabilities.requiredPrimitives, P::MlaDecompressFwd) &&
          Contains(loaded.capabilities.availablePrimitives, P::MlaDecompressFwd) &&
          !Contains(loaded.capabilities.unimplementedPrimitives, P::MlaDecompressFwd),
          "actual reader ignores stale historical MLA boundary");
    Check(loadedOk && Partitioned(loaded.capabilities) && loaded.capabilities.runtimeExecutable &&
          loaded.capabilities.firstUnimplementedPrimitive == P::None,
          "actual reader derives complete binding manifest");
    std::printf("MODELGENOME_CAPABILITIES_RESULT %s checks=%d failures=%d scope=primitive-bindings-only\n",
                failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
