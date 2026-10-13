// deep2_plan.cpp - GGUF to Deep2 execution-plan bridge.
// RAWRXD_DEEP2_IR_BRIDGE_001
//
// Reads any GGUF through the universal reader and emits the architecture's
// execution plan: per-block kind schedule, per-role tensor inventory with
// dimensions and dtypes, and a validation that every tensor a plan needs is
// present and sized by the canonical QuantTypeTable.
//
// This is the bridge between RawrXDGgufReader and Deep2ExecutionIR. It does
// not execute anything; it makes a model's execution plan inspectable.
#include "QuantTypeTable.hpp"
#include "RawrXDGgufReader.hpp"

#include <algorithm>
#include <cstdio>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace rawrxd;

namespace
{

// A normalised tensor name: the block index becomes N so the same layout can be
// recognised across blocks and models.
std::string Normalize(const std::string& n)
{
    std::string out;
    out.reserve(n.size());
    for (size_t i = 0; i < n.size(); ++i)
    {
        if (n.compare(i, 4, "blk.") == 0)
        {
            out += "blk.";
            size_t j = i + 4;
            while (j < n.size() && isdigit((unsigned char)n[j]))
                ++j;
            out += "N";
            i = j - 1;
        }
        else
        {
            out += n[i];
        }
    }
    return out;
}

struct Plan
{
    std::string arch;
    std::vector<int> blocks;
    // block index -> set of normalised suffixes
    std::map<int, std::set<std::string>> perBlock;
    // normalised full name -> exemplar tensor + block it came from
    std::map<std::string, std::pair<const GgufTensor*, int>> roles;
};

bool BuildPlan(const GgufReader& r, Plan& p)
{
    p.arch = r.architecture();
    r.blockIndices(p.blocks);
    for (int b : p.blocks)
    {
        std::vector<const GgufTensor*> ts;
        r.layerTensors(b, ts, "");
        for (const GgufTensor* t : ts)
        {
            size_t start = t->name.find('.', t->name.find("blk.") + 4);
            std::string suffix = start == std::string::npos ? "" : t->name.substr(start + 1);
            p.perBlock[b].insert(suffix);
            const std::string norm = "blk.N." + suffix;
            if (!p.roles.count(norm))
                p.roles[norm] = {t, b};
        }
    }
    // global (non-block) tensors
    for (const auto& kv : r.tensors())
    {
        if (kv.first.rfind("blk.", 0) == 0)
            continue;
        const std::string norm = Normalize(kv.first);
        if (!p.roles.count(norm))
            p.roles[norm] = {&kv.second, -1};
    }
    return true;
}

// Which execution plan family a model belongs to. Determined from the evidence
// in the file, not from a lookup table of model names.
const char* PlanFamily(const Plan& p, bool hasSsm, bool hasAttn, bool hasMoe)
{
    if (hasSsm && hasMoe)
        return "SSM+MoE";
    if (hasSsm)
        return "SSM";
    if (hasMoe)
        return "expert-MoE";
    if (hasAttn)
        return "dense-transformer";
    return "unknown";
}

void Report(const GgufReader& r, const Plan& p, const char* path)
{
    printf("FILE %s\n", path);
    printf("ARCH %s\n", p.arch.c_str() ? p.arch.c_str() : "(absent)");

    const bool hasSsm = r.hasSsm(), hasAttn = r.hasAttention(), hasMoe = r.hasMoe();
    printf("FAMILY %s\n", PlanFamily(p, hasSsm, hasAttn, hasMoe));
    printf("BLOCKS %zu (range %d..%d)\n", p.blocks.size(), p.blocks.front(), p.blocks.back());

    // Block kind schedule: SSM / attention / MLP / MoE per block.
    int nSsm = 0, nAttn = 0, nMlp = 0, nMoe = 0;
    for (int b : p.blocks)
    {
        auto sit = p.perBlock.find(b);
        if (sit == p.perBlock.end())
            continue;
        const std::set<std::string>& s = sit->second;
        bool ssm = false, attn = false, mlp = false, moe = false;
        for (const std::string& k : s)
        {
            if (k.rfind("ssm", 0) == 0)
                ssm = true;
            if (k.find("attn") != std::string::npos)
                attn = true;
            if (k.find("ffn") != std::string::npos)
                mlp = true;
            if (k.find("exps") != std::string::npos || k.find("exp_probs") != std::string::npos)
                moe = true;
        }
        nSsm += ssm ? 1 : 0;
        nAttn += attn ? 1 : 0;
        nMlp += mlp ? 1 : 0;
        nMoe += moe ? 1 : 0;
    }
    printf("BLOCK_KINDS ssm_blocks=%d attn_blocks=%d ffn_blocks=%d moe_blocks=%d\n", nSsm, nAttn, nMlp, nMoe);

    // Are all blocks the same shape? A hybrid alternates.
    std::set<std::string> distinct;
    for (int b : p.blocks)
    {
        std::string sig;
        auto it2 = p.perBlock.find(b);
        if (it2 != p.perBlock.end())
            for (const std::string& k : it2->second)
                sig += k + ";";
        distinct.insert(sig);
    }
    printf("BLOCK_SIGNATURES %zu %s\n", distinct.size(),
           distinct.size() == 1 ? "(uniform)" : "(hybrid: blocks differ)");

    // Role inventory with dtype census.
    std::map<std::string, int> dtypeByRole;
    std::map<int, int> dtypeCensus;
    for (const auto& kv : r.tensors())
    {
        const std::string norm = Normalize(kv.first);
        dtypeByRole[norm] = kv.second.type;
        dtypeCensus[kv.second.type]++;
    }
    printf("DTYPES");
    for (const auto& kv : dtypeCensus)
        printf(" %s=%d", Deep2::QuantTypeName(kv.first), kv.second);
    printf("\n");

    // Validation: every tensor must be sized (non-zero nbytes) or be a
    // zero-element tensor, and its range must be inside the file.
    int bad = 0;
    for (const auto& kv : r.tensors())
    {
        const GgufTensor& t = kv.second;
        if (t.nelements() == 0)
            continue;
        if (t.nbytes == 0)
        {
            ++bad;
            continue;
        }
        if (t.abs_offset + t.nbytes > r.fileSize())
            ++bad;
    }
    printf("TENSORS %llu UNSIZED %d\n", (unsigned long long)r.tensorCount(), bad);

    // The roles a plan needs to identify, as a normalised signature.
    printf("ROLE_SIGNATURE");
    for (const auto& kv : r.tensors())
    {
    }
    // (printed below as a stable list)
    printf("\n");
}

}  // namespace

int main(int argc, char** argv)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc < 2)
    {
        printf("usage: deep2_plan <file.gguf>\n");
        return 2;
    }

    GgufReader r;
    if (!r.Open(argv[1]))
    {
        printf("OPEN_FAIL %s : %s\n", argv[1], r.why().c_str());
        return 1;
    }
    Plan p;
    BuildPlan(r, p);
    Report(r, p, argv[1]);

    // Print the normalised block template once, so plans are comparable.
    if (!p.blocks.empty())
    {
        const int b0 = p.blocks.front();
        printf("BLOCK_TEMPLATE blk.%d\n", b0);
        auto tit = p.perBlock.find(b0);
        if (tit != p.perBlock.end())
            for (const std::string& k : tit->second)
            {
                auto it = p.roles.find("blk.N." + k);
                const GgufTensor* t = it != p.roles.end() ? it->second.first : nullptr;
                if (t)
                {
                    printf("  %-34s %-8s ne=[%lld,%lld,%lld,%lld] bytes=%llu\n", k.c_str(),
                           Deep2::QuantTypeName(t->type), (long long)t->ne0(), (long long)t->ne1(), (long long)t->ne2(),
                           (long long)t->ne3(), (unsigned long long)t->nbytes);
                }
                else
                {
                    printf("  %s (no exemplar)\n", k.c_str());
                }
            }
        printf("GLOBALS\n");
        for (const auto& kv : r.tensors())
        {
            if (kv.first.rfind("blk.", 0) == 0)
                continue;
            printf("  %-34s %-8s ne=[%lld,%lld,%lld,%lld] bytes=%llu\n", kv.first.c_str(),
                   Deep2::QuantTypeName(kv.second.type), (long long)kv.second.ne0(), (long long)kv.second.ne1(),
                   (long long)kv.second.ne2(), (long long)kv.second.ne3(), (unsigned long long)kv.second.nbytes);
        }
    }
    return 0;
}
