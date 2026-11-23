#include "../../src/deep2/compression/CompressedTransformerRuntime.hpp"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdint>
#include <cstring>
#include <future>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
struct OwnedTensor {
    std::string name;
    std::vector<std::int64_t> shape;
    std::vector<std::uint8_t> bytes;
    std::uint32_t type = 1; // GGML_TYPE_F16
};
float decodeHalfForFixture(std::uint16_t h) {
    const std::uint32_t sign = std::uint32_t(h & 0x8000u) << 16;
    const std::uint32_t exp = (h >> 10) & 31u;
    const std::uint32_t frac = h & 1023u;
    std::uint32_t bits = sign;
    if (exp == 31u) bits |= 0x7f800000u | (frac << 13);
    else if (exp) bits |= ((exp + 112u) << 23) | (frac << 13);
    else if (frac) {
        std::uint32_t m = frac;
        int e = -14;
        while ((m & 0x400u) == 0) { m <<= 1; --e; }
        bits |= (std::uint32_t(e + 127) << 23) | ((m & 0x3ffu) << 13);
    }
    float value = 0.0f;
    std::memcpy(&value, &bits, sizeof(value));
    return value;
}
std::uint16_t encodeBFloat16ForFixture(float value) {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    const std::uint32_t upper = bits >> 16;
    const std::uint32_t rounded = bits + 0x7fffu + (upper & 1u);
    return static_cast<std::uint16_t>(rounded >> 16);
}
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

float referenceHalfToFloat(std::uint16_t h) {
    const std::uint32_t sign=std::uint32_t(h&0x8000u)<<16;
    std::uint32_t exp=(h>>10)&31u, mant=h&1023u, bits=0;
    if(exp==0) {
        if(!mant) bits=sign;
        else { int e=-14; while((mant&0x400u)==0){mant<<=1;--e;}
            mant&=0x3ffu; bits=sign|(std::uint32_t(e+127)<<23)|(mant<<13); }
    } else if(exp==31) bits=sign|0x7f800000u|(mant<<13);
    else bits=sign|((exp+112u)<<23)|(mant<<13);
    float value=0.0f; std::memcpy(&value,&bits,sizeof(value)); return value;
}
const OwnedTensor& referenceTensor(const std::vector<OwnedTensor>& tensors,
                                   const std::string& name) {
    for(const auto& tensor:tensors) if(tensor.name==name) return tensor;
    throw std::runtime_error("reference tensor missing: "+name);
}
std::vector<float> referenceValues(const std::vector<OwnedTensor>& tensors,
                                   const std::string& name) {
    const auto& tensor=referenceTensor(tensors,name);
    if(tensor.type != rawrxd::compression::GGML_TYPE_F16 &&
       tensor.type != rawrxd::compression::GGML_TYPE_BF16)
        throw std::runtime_error("reference only supports F16 and BF16");
    if(tensor.bytes.size()%2) throw std::runtime_error("reference tensor has odd byte length");
    std::vector<float> values(tensor.bytes.size()/2);
    for(std::size_t i=0;i<values.size();++i) {
        const std::uint16_t word=std::uint16_t(tensor.bytes[2*i])|
                                 (std::uint16_t(tensor.bytes[2*i+1])<<8);
        if(tensor.type == rawrxd::compression::GGML_TYPE_F16) {
            values[i]=referenceHalfToFloat(word);
        } else {
            const std::uint32_t bits=std::uint32_t(word)<<16;
            std::memcpy(&values[i],&bits,sizeof(float));
        }
    }
    return values;
}
std::vector<float> referenceMatvec(const std::vector<OwnedTensor>& tensors,
    const std::string& name,const std::vector<float>& input,
    std::size_t rows,std::size_t cols) {
    const auto weights=referenceValues(tensors,name);
    if(weights.size()!=rows*cols||input.size()!=cols)
        throw std::runtime_error("reference matvec geometry mismatch: "+name);
    std::vector<float> output(rows,0.0f);
    for(std::size_t row=0;row<rows;++row)
        for(std::size_t col=0;col<cols;++col)
            output[row]+=weights[row*cols+col]*input[col];
    return output;
}
void referenceRmsNorm(const std::vector<OwnedTensor>& tensors,
    std::vector<float>& x,const std::string& name,float epsilon) {
    const auto weights=referenceValues(tensors,name);
    if(weights.size()!=x.size()) throw std::runtime_error("reference norm geometry mismatch");
    double sum=0.0; for(float value:x) sum+=static_cast<double>(value)*value;
    const float inv=1.0f/std::sqrt(static_cast<float>(sum/x.size())+epsilon);
    for(std::size_t i=0;i<x.size();++i) x[i]=x[i]*inv*weights[i];
}
void referenceRope(std::vector<float>& x,std::size_t position,
    std::size_t headCount,std::size_t headDim,float theta) {
    if(x.size()!=headCount*headDim) throw std::runtime_error("reference RoPE geometry mismatch");
    for(std::size_t head=0;head<headCount;++head) {
        const auto base=head*headDim;
        for(std::size_t d=0;d<headDim;d+=2) {
            const float frequency=1.0f/std::pow(theta,static_cast<float>(d)/headDim);
            const float angle=static_cast<float>(position)*frequency;
            const float cosine=std::cos(angle),sine=std::sin(angle);
            const float a=x[base+d],b=x[base+d+1];
            x[base+d]=a*cosine-b*sine; x[base+d+1]=a*sine+b*cosine;
        }
    }
}
// Independent dense oracle: reads the fixture's original F16 byte vectors,
// performs scalar GEMVs and recomputes the KV cache without using the compressed
// store, its block decoder, or its matvec implementation.
std::vector<int32_t> referenceGenerate(const std::vector<OwnedTensor>& tensors,
    const std::vector<int32_t>& prompt,std::size_t steps,std::size_t hidden,
    std::size_t intermediate,std::size_t vocabulary,std::size_t layers,
    std::size_t queryHeads,std::size_t kvHeads,std::size_t headDim,
    float epsilon,float ropeTheta) {
    if(!kvHeads) kvHeads=queryHeads;
    if(!kvHeads||queryHeads%kvHeads) throw std::runtime_error("reference GQA geometry mismatch");
    std::vector<std::vector<std::vector<float>>> keys(layers),values(layers);
    auto forward=[&](int32_t token,std::size_t position) {
        const auto embedding=referenceValues(tensors,"token_embd.weight");
        if(token<0||static_cast<std::size_t>(token)>=vocabulary||
           embedding.size()!=vocabulary*hidden)
            throw std::runtime_error("reference embedding geometry mismatch");
        std::vector<float> hiddenState(embedding.begin()+static_cast<std::size_t>(token)*hidden,
            embedding.begin()+(static_cast<std::size_t>(token)+1)*hidden);
        const std::size_t kvDim=kvHeads*headDim;
        for(std::size_t layer=0;layer<layers;++layer) {
            const auto prefix="blk."+std::to_string(layer)+".";
            auto residual=hiddenState,normed=hiddenState;
            referenceRmsNorm(tensors,normed,prefix+"attn_norm.weight",epsilon);
            auto q=referenceMatvec(tensors,prefix+"attn_q.weight",normed,hidden,hidden);
            auto k=referenceMatvec(tensors,prefix+"attn_k.weight",normed,kvDim,hidden);
            auto v=referenceMatvec(tensors,prefix+"attn_v.weight",normed,kvDim,hidden);
            referenceRope(q,position,queryHeads,headDim,ropeTheta);
            referenceRope(k,position,kvHeads,headDim,ropeTheta);
            keys[layer].push_back(k); values[layer].push_back(v);
            std::vector<float> attended(hidden,0.0f);
            const std::size_t headsPerKv=queryHeads/kvHeads;
            for(std::size_t head=0;head<queryHeads;++head) {
                const auto queryBase=head*headDim;
                const auto kvBase=(head/headsPerKv)*headDim;
                std::vector<float> scores(keys[layer].size());
                float maximum=-std::numeric_limits<float>::infinity();
                for(std::size_t t=0;t<keys[layer].size();++t) {
                    double dot=0.0;
                    for(std::size_t d=0;d<headDim;++d)
                        dot+=static_cast<double>(q[queryBase+d])*keys[layer][t][kvBase+d];
                    scores[t]=static_cast<float>(dot/std::sqrt(static_cast<float>(headDim)));
                    maximum=std::max(maximum,scores[t]);
                }
                double denominator=0.0;
                for(float& score:scores){score=std::exp(score-maximum);denominator+=score;}
                for(std::size_t t=0;t<scores.size();++t) {
                    const float probability=static_cast<float>(scores[t]/denominator);
                    for(std::size_t d=0;d<headDim;++d)
                        attended[queryBase+d]+=probability*values[layer][t][kvBase+d];
                }
            }
            auto attentionOutput=referenceMatvec(tensors,prefix+"attn_output.weight",
                attended,hidden,hidden);
            for(std::size_t i=0;i<hidden;++i) hiddenState[i]=residual[i]+attentionOutput[i];
            residual=hiddenState; normed=hiddenState;
            referenceRmsNorm(tensors,normed,prefix+"ffn_norm.weight",epsilon);
            auto gate=referenceMatvec(tensors,prefix+"ffn_gate.weight",normed,intermediate,hidden);
            auto up=referenceMatvec(tensors,prefix+"ffn_up.weight",normed,intermediate,hidden);
            for(std::size_t i=0;i<intermediate;++i) {
                const float sigmoid=1.0f/(1.0f+std::exp(-gate[i]));
                gate[i]=gate[i]*sigmoid*up[i];
            }
            auto down=referenceMatvec(tensors,prefix+"ffn_down.weight",gate,hidden,intermediate);
            for(std::size_t i=0;i<hidden;++i) hiddenState[i]=residual[i]+down[i];
        }
        referenceRmsNorm(tensors,hiddenState,"output_norm.weight",epsilon);
        return referenceMatvec(tensors,"output.weight",hiddenState,vocabulary,hidden);
    };
    std::vector<float> logits;
    std::size_t position=0;
    for(const auto token:prompt) logits=forward(token,position++);
    std::vector<int32_t> generated;
    for(std::size_t n=0;n<steps;++n) {
        const auto next=static_cast<int32_t>(std::distance(logits.begin(),
            std::max_element(logits.begin(),logits.end())));
        generated.push_back(next);
        if(n+1<steps) logits=forward(next,position++);
    }
    return generated;
}
std::vector<Deep2::GGUFTensor> descriptors(std::vector<OwnedTensor>& owned) {
    std::vector<Deep2::GGUFTensor> out;
    out.reserve(owned.size());
    for (auto& src : owned) {
        Deep2::GGUFTensor t;
        t.name = src.name;
        t.type = static_cast<Deep2::GGMLType>(src.type);
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

    // A second copy of the complete synthetic model uses BF16 payloads.
    // Convert the F16 fixture values back to F32 before rounding to BF16 so
    // the test exercises the BF16 wire representation rather than aliasing
    // the IEEE F16 bit layout.
    auto bf16Owned = owned;
    for (auto& tensor : bf16Owned) {
        std::vector<std::uint8_t> converted;
        converted.reserve(tensor.bytes.size());
        for (std::size_t i = 0; i + 1 < tensor.bytes.size(); i += 2) {
            const std::uint16_t half = std::uint16_t(tensor.bytes[i]) |
                                       (std::uint16_t(tensor.bytes[i + 1]) << 8);
            const std::uint16_t bf16 = encodeBFloat16ForFixture(decodeHalfForFixture(half));
            converted.push_back(static_cast<std::uint8_t>(bf16 & 0xffu));
            converted.push_back(static_cast<std::uint8_t>(bf16 >> 8));
        }
        tensor.bytes.swap(converted);
        tensor.type = rawrxd::compression::GGML_TYPE_BF16;
    }
    auto bf16Tensors = descriptors(bf16Owned);
    rawrxd::compression::CompressedGGUFModel bf16Model(storeOptions);
    assert(bf16Model.loadMappedTensors(bf16Tensors, &error, &failed));
    rawrxd::compression::CompressedTransformerRuntime bf16Runtime(bf16Model, config);
    const auto bf16Generated = bf16Runtime.generate(prompt, 3);
    assert(bf16Generated.size() == 3);
    for (auto token : bf16Generated)
        assert(token >= 0 && token < static_cast<int32_t>(vocab));
    assert(bf16Runtime.generate(prompt, 3) == bf16Generated);
    // The dense oracle reads the original BF16 fixture bytes and performs
    // independent scalar projections without the compressed store/reader.
    const auto bf16Reference = referenceGenerate(bf16Owned, prompt, 3, hidden,
        intermediate, vocab, 2, 2, 0, hidden/2, config.rms_epsilon,
        config.rope_theta);
    assert(bf16Generated == bf16Reference);
    assert(bf16Model.stats().cached_decoded_bytes == 0);

    const auto generated=runtime.generate(prompt,6);
    assert(generated.size()==6);
    for(auto token:generated) assert(token>=0 && token<static_cast<int32_t>(vocab));

    // Independent scalar-reference golden sequence for this fixed F16 fixture.
    // This catches numerically wrong but deterministic generation paths.
    const std::vector<int32_t> expected{7,7,7,7,7,7};
    assert(generated == expected);
    const auto denseReference = referenceGenerate(owned, prompt, 6, hidden,
        intermediate, vocab, 2, 2, 0, hidden/2, config.rms_epsilon,
        config.rope_theta);
    assert(generated == denseReference);
    // Exact context-boundary admission: generating the final allowed token
    // must not perform an additional, unneeded transformer forward.
    auto exactContext = config;
    exactContext.max_context = prompt.size() + 2;
    rawrxd::compression::CompressedTransformerRuntime exactRuntime(model, exactContext);
    const auto boundaryTokens = exactRuntime.generate(prompt, 2);
    assert(boundaryTokens.size() == 2);
    assert(boundaryTokens == std::vector<int32_t>(generated.begin(), generated.begin()+2));
    // Admission must charge only actual forward passes, not the final token
    // that is emitted directly from the preceding logits.
    auto exactKvBudget = exactContext;
    // kv_heads=0 means MHA, resolved to heads in the runtime constructor.
    const std::size_t resolvedKvBytesPerToken =
        exactKvBudget.layers * 2u * exactKvBudget.heads * exactKvBudget.head_dim * sizeof(float);
    exactKvBudget.max_kv_cache_bytes =
        (prompt.size() + 2u - 1u) * resolvedKvBytesPerToken;
    rawrxd::compression::CompressedTransformerRuntime budgetRuntime(model, exactKvBudget);
    assert(budgetRuntime.generate(prompt, 2) == boundaryTokens);
    exactKvBudget.max_kv_cache_bytes -= 1u;
    rawrxd::compression::CompressedTransformerRuntime insufficientBudget(model, exactKvBudget);
    bool kvBudgetRejected = false;
    try { (void)insufficientBudget.generate(prompt, 2); }
    catch (const std::length_error&) { kvBudgetRejected = true; }
    assert(kvBudgetRejected);

    bool contextOverflowRejected = false;
    try { (void)exactRuntime.generate(prompt, 3); }
    catch (const std::out_of_range&) { contextOverflowRejected = true; }
    assert(contextOverflowRejected);


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
    // 2 layers * 3 forwarded positions * 2 KV values * K+V * sizeof(float).
    // The final emitted token does not enter the KV cache.
    gqaConfig.max_kv_cache_bytes = 96;
    rawrxd::compression::CompressedTransformerRuntime gqaRuntime(gqaModel, gqaConfig);
    const auto gqaGenerated = gqaRuntime.generate(prompt, 2);
    assert(gqaGenerated.size() == 2);
    for (auto token : gqaGenerated)
        assert(token >= 0 && token < static_cast<int32_t>(vocab));
    assert(gqaRuntime.generate(prompt, 2) == gqaGenerated);
    const auto gqaReference = referenceGenerate(gqaOwned, prompt, 2, hidden,
        intermediate, vocab, 2, 2, 1, hidden/2, gqaConfig.rms_epsilon,
        gqaConfig.rope_theta);
    assert(gqaGenerated == gqaReference);

    auto tooSmallGqaCache = gqaConfig;
    tooSmallGqaCache.max_kv_cache_bytes = 95;
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

    // A malformed sampler geometry must not silently truncate vocabulary
    // indices into the int32_t token domain.
    auto invalidVocabulary = config;
    invalidVocabulary.vocabulary =
        static_cast<std::size_t>((std::numeric_limits<int32_t>::max)()) + 1u;
    bool rejectedVocabulary = false;
    try { rawrxd::compression::CompressedTransformerRuntime bad(model, invalidVocabulary); }
    catch (const std::invalid_argument&) { rejectedVocabulary = true; }
    assert(rejectedVocabulary);

    auto invalidRms = config;
    invalidRms.rms_epsilon = (std::numeric_limits<float>::infinity)();
    bool rejectedRms = false;
    try { rawrxd::compression::CompressedTransformerRuntime bad(model, invalidRms); }
    catch (const std::invalid_argument&) { rejectedRms = true; }
    assert(rejectedRms);

    auto invalidRope = config;
    invalidRope.rope_theta = (std::numeric_limits<float>::quiet_NaN)();
    bool rejectedRope = false;
    try { rawrxd::compression::CompressedTransformerRuntime bad(model, invalidRope); }
    catch (const std::invalid_argument&) { rejectedRope = true; }
    assert(rejectedRope);

    const auto stats=model.stats();
    assert(stats.tensors==owned.size());
    assert(stats.compressed_bytes>0 && stats.raw_bytes>0);
    assert(stats.cached_decoded_bytes==0);
    assert(stats.cache_misses>0);
    return 0;
}
