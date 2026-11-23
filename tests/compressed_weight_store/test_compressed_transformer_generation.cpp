#include "../../src/deep2/compression/CompressedTransformerRuntime.hpp"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdint>
#include <future>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
struct OwnedTensor {
    std::string name;
    std::vector<std::int64_t> shape;
    std::vector<std::uint8_t> bytes;
};
void appendF16(OwnedTensor& t, float value) {
    const auto h = rawrxd::compression::floatToHalfRNE(value);
    t.bytes.push_back(static_cast<std::uint8_t>(h & 0xffu));
    t.bytes.push_back(static_cast<std::uint8_t>(h >> 8));
}
void addVector(std::vector<OwnedTensor>& all, const std::string& name,
               const std::vector<float>& values) {
    OwnedTensor t{name, {static_cast<std::int64_t>(values.size())}, {}};
    for (float v : values) appendF16(t, v);
    all.emplace_back(std::move(t));
}
void addMatrix(std::vector<OwnedTensor>& all, const std::string& name,
               std::size_t rows, std::size_t cols,
               const std::vector<float>& values) {
    assert(values.size() == rows * cols);
    OwnedTensor t{name, {static_cast<std::int64_t>(cols),
                         static_cast<std::int64_t>(rows)}, {}};
    for (float v : values) appendF16(t, v);
    all.emplace_back(std::move(t));
}
std::vector<float> diagonal(std::size_t n, float scale) {
    std::vector<float> v(n*n, 0.0f);
    for (std::size_t i=0;i<n;++i) v[i*n+i]=scale;
    return v;
}
std::vector<Deep2::GGUFTensor> descriptors(std::vector<OwnedTensor>& owned) {
    std::vector<Deep2::GGUFTensor> out;
    out.reserve(owned.size());
    for (auto& src : owned) {
        Deep2::GGUFTensor t;
        t.name = src.name;
        t.type = static_cast<Deep2::GGMLType>(1); // GGML_TYPE_F16
        t.shape = src.shape;
        t.data = src.bytes.data();
        t.sizeBytes = src.bytes.size();
        t.mapped = true;
        out.emplace_back(std::move(t));
    }
    return out;
}
} // namespace

int main() {
    constexpr std::size_t hidden=4, intermediate=8, vocab=8;
    std::vector<OwnedTensor> owned;
    owned.reserve(24);

    std::vector<float> embedding(vocab*hidden);
    for (std::size_t r=0;r<vocab;++r) {
        embedding[r*hidden+0]=0.10f*float(r+1);
        embedding[r*hidden+1]=0.05f*float(r%3);
        embedding[r*hidden+2]=0.025f*float(r%2);
        embedding[r*hidden+3]=-0.02f*float(r);
    }
    addMatrix(owned,"token_embd.weight",vocab,hidden,embedding);
    addVector(owned,"output_norm.weight",std::vector<float>(hidden,1.0f));
    std::vector<float> output(vocab*hidden);
    for(std::size_t r=0;r<vocab;++r)
        for(std::size_t c=0;c<hidden;++c)
            output[r*hidden+c]=0.05f*float(int((r*3+c*5)%11)-5);
    addMatrix(owned,"output.weight",vocab,hidden,output);

    // Two complete pre-norm decoder blocks, each with multi-head causal
    // self-attention, RoPE, residual paths, SwiGLU and a second residual.
    for (std::size_t layer=0; layer<2; ++layer) {
        const std::string p="blk."+std::to_string(layer)+".";
        const float layerScale = layer==0 ? 1.0f : 0.8f;
        addVector(owned,p+"attn_norm.weight",std::vector<float>(hidden,1.0f));
        addMatrix(owned,p+"attn_q.weight",hidden,hidden,diagonal(hidden,0.75f*layerScale));
        addMatrix(owned,p+"attn_k.weight",hidden,hidden,diagonal(hidden,0.50f*layerScale));
        addMatrix(owned,p+"attn_v.weight",hidden,hidden,diagonal(hidden,1.0f));
        addMatrix(owned,p+"attn_output.weight",hidden,hidden,diagonal(hidden,1.0f));
        addVector(owned,p+"ffn_norm.weight",std::vector<float>(hidden,1.0f));

        std::vector<float> gate(intermediate*hidden), up(intermediate*hidden);
        for(std::size_t r=0;r<intermediate;++r)
            for(std::size_t col=0;col<hidden;++col) {
                gate[r*hidden+col]=0.04f*layerScale*float(1+((r+col)%4));
                up[r*hidden+col]=0.10f*float(1+((2*r+col+layer)%3));
            }
        addMatrix(owned,p+"ffn_gate.weight",intermediate,hidden,gate);
        addMatrix(owned,p+"ffn_up.weight",intermediate,hidden,up);
        std::vector<float> down(hidden*intermediate,0.0f);
        for(std::size_t r=0;r<hidden;++r)
            for(std::size_t col=0;col<intermediate;++col)
                down[r*intermediate+col]=(col%hidden==r)?0.25f:0.025f;
        addMatrix(owned,p+"ffn_down.weight",hidden,intermediate,down);
    }

    auto tensors=descriptors(owned);
    rawrxd::compression::CompressedGGUFModel::Options storeOptions;
    storeOptions.decoded_cache_bytes=0;
    storeOptions.block_bytes=64;
    storeOptions.require_savings=false;
    rawrxd::compression::CompressedGGUFModel model(storeOptions);
    std::string error, failed;
    assert(model.loadMappedTensors(tensors,&error,&failed));
    assert(model.loaded() && model.tensorCount()==owned.size());
    assert(model.stats().cached_decoded_bytes==0);

    rawrxd::compression::CompressedTransformerRuntime::Config config;
    config.hidden=hidden;
    config.intermediate=intermediate;
    config.vocabulary=vocab;
    config.layers=2;
    config.heads=2;
    config.head_dim=hidden/2;
    config.rms_epsilon=1.0e-5f;
    config.rope_theta=10000.0f;

    rawrxd::compression::CompressedTransformerRuntime runtime(model,config);
    const std::vector<int32_t> prompt{1,2};
    const auto generated=runtime.generate(prompt,6);
    assert(generated.size()==6);
    for(auto token:generated) assert(token>=0 && token<static_cast<int32_t>(vocab));

    // Independent scalar-reference golden sequence for this fixed F16 fixture.
    // This catches numerically wrong but deterministic generation paths.
    const std::vector<int32_t> expected{7,7,7,7,7,7};
    assert(generated == expected);

    // Request-local KV state must reset between generations.
    const auto repeated=runtime.generate(prompt,6);
    assert(repeated==generated);

    // Independent requests share immutable compressed weights but never share
    // KV state or scratch readers. Exercise concurrent autoregressive decode.
    auto requestA = std::async(std::launch::async, [&] { return runtime.generate(prompt, 6); });
    auto requestB = std::async(std::launch::async, [&] { return runtime.generate(prompt, 6); });
    assert(requestA.get() == generated);
    assert(requestB.get() == generated);

    // Grouped-query attention: two query heads share one compact KV head.
    // K/V tensors therefore contain kv_heads * head_dim rows rather than
    // heads * head_dim rows, and the request cache must use the smaller shape.
    auto gqaOwned = owned;
    for (auto& tensor : gqaOwned) {
        if (tensor.name.size() >= 13 &&
            (tensor.name.compare(tensor.name.size() - 13, 13, "attn_k.weight") == 0 ||
             tensor.name.compare(tensor.name.size() - 13, 13, "attn_v.weight") == 0)) {
            tensor.shape = {static_cast<std::int64_t>(hidden), 2};
            tensor.bytes.clear();
            const std::vector<float> values =
                tensor.name.compare(tensor.name.size() - 13, 13, "attn_k.weight") == 0
                    ? std::vector<float>{0.5f,0.1f,-0.1f,0.0f,-0.2f,0.4f,0.1f,0.3f}
                    : std::vector<float>{1.0f,0.1f,0.0f,0.2f,-0.1f,0.8f,0.3f,-0.2f};
            for (float value : values) appendF16(tensor, value);
        }
    }
    auto gqaTensors = descriptors(gqaOwned);
    rawrxd::compression::CompressedGGUFModel gqaModel(storeOptions);
    assert(gqaModel.loadMappedTensors(gqaTensors, &error, &failed));
    auto gqaConfig = config;
    gqaConfig.kv_heads = 1;
    // 2 layers * 4 cached positions * 2 KV values * K+V * sizeof(float).
    gqaConfig.max_kv_cache_bytes = 128;
    rawrxd::compression::CompressedTransformerRuntime gqaRuntime(gqaModel, gqaConfig);
    const auto gqaGenerated = gqaRuntime.generate(prompt, 2);
    assert(gqaGenerated.size() == 2);
    for (auto token : gqaGenerated)
        assert(token >= 0 && token < static_cast<int32_t>(vocab));
    assert(gqaRuntime.generate(prompt, 2) == gqaGenerated);

    auto tooSmallGqaCache = gqaConfig;
    tooSmallGqaCache.max_kv_cache_bytes = 127;
    rawrxd::compression::CompressedTransformerRuntime tooSmallGqa(gqaModel, tooSmallGqaCache);
    bool rejectedGqaCache = false;
    try { (void)tooSmallGqa.generate(prompt, 2); }
    catch (const std::length_error&) { rejectedGqaCache = true; }
    assert(rejectedGqaCache);

    auto invalidKvHeads = config;
    invalidKvHeads.kv_heads = 3;
    bool rejectedKvHeads = false;
    try { rawrxd::compression::CompressedTransformerRuntime badKvHeads(model, invalidKvHeads); }
    catch (const std::invalid_argument&) { rejectedKvHeads = true; }
    assert(rejectedKvHeads);

    // Reject invalid prompts and inconsistent attention geometry before doing
    // any weight reads or allocating a request KV cache.
    bool rejectedPrompt=false;
    try { (void)runtime.generate({-1},1); }
    catch (const std::out_of_range&) { rejectedPrompt=true; }
    assert(rejectedPrompt);

    bool rejectedGeometry=false;
    try {
        auto invalid=config;
        invalid.head_dim=1;
        rawrxd::compression::CompressedTransformerRuntime bad(model,invalid);
    } catch (const std::invalid_argument&) { rejectedGeometry=true; }
    assert(rejectedGeometry);

    auto bounded=config;
    bounded.max_context=3;
    rawrxd::compression::CompressedTransformerRuntime boundedRuntime(model,bounded);
    bool rejectedContext=false;
    try { (void)boundedRuntime.generate(prompt,2); }
    catch (const std::out_of_range&) { rejectedContext=true; }
    assert(rejectedContext);

    auto cacheBounded=config;
    cacheBounded.max_kv_cache_bytes=1;
    rawrxd::compression::CompressedTransformerRuntime cacheBoundedRuntime(model,cacheBounded);
    bool rejectedCacheBudget=false;
    try { (void)cacheBoundedRuntime.generate(prompt,1); }
    catch (const std::length_error&) { rejectedCacheBudget=true; }
    assert(rejectedCacheBudget);

    auto invalidEos=config;
    invalidEos.eos_token=static_cast<int32_t>(vocab);
    bool rejectedEos=false;
    try { rawrxd::compression::CompressedTransformerRuntime badEos(model,invalidEos); }
    catch (const std::invalid_argument&) { rejectedEos=true; }
    assert(rejectedEos);

    const auto stats=model.stats();
    assert(stats.tensors==owned.size());
    assert(stats.compressed_bytes>0 && stats.raw_bytes>0);
    assert(stats.cached_decoded_bytes==0);
    assert(stats.cache_misses>0);
    return 0;
}
