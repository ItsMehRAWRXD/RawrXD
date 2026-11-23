#include "../../src/deep2/GGUFLoader.hpp"
#include "../../src/deep2/compression/GGUFCompressedResidency.hpp"
#include "../../src/deep2/compression/StoredTensorMatvec.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

#define REQUIRE(x) do { if (!(x)) { std::cerr << "FAIL: " #x << " at " << __LINE__ << "\n"; return 1; } } while (false)

namespace {
void put32(std::vector<std::uint8_t>& b, std::uint32_t v) {
    for (unsigned i=0;i<4;++i) b.push_back(static_cast<std::uint8_t>(v>>(8*i)));
}
void put64(std::vector<std::uint8_t>& b, std::uint64_t v) {
    for (unsigned i=0;i<8;++i) b.push_back(static_cast<std::uint8_t>(v>>(8*i)));
}
void putString(std::vector<std::uint8_t>& b, const std::string& s) {
    put64(b, s.size()); b.insert(b.end(), s.begin(), s.end());
}
void align32(std::vector<std::uint8_t>& b) {
    while (b.size() % 32) b.push_back(0);
}
std::vector<std::uint8_t> makeQ4ModelTensor(std::size_t rows, std::size_t cols) {
    const std::size_t rowBytes=(cols/32)*18;
    std::vector<std::uint8_t> bytes(rows*rowBytes, 0);
    for (std::size_t row=0; row<rows; ++row) {
        for (std::size_t block=0; block<cols/32; ++block) {
            const std::size_t base=row*rowBytes+block*18;
            bytes[base]=0x00; bytes[base+1]=0x3c; // fp16 scale = 1
            for (std::size_t i=0;i<16;++i) bytes[base+2+i]=0x98;
        }
    }
    return bytes;
}
void putTensorDescriptor(std::vector<std::uint8_t>& file,
                         const std::string& name,
                         std::uint64_t cols, std::uint64_t rows,
                         std::uint32_t type, std::uint64_t offset) {
    putString(file,name);
    put32(file,2); put64(file,cols); put64(file,rows);
    put32(file,type); put64(file,offset);
}
void putVectorDescriptor(std::vector<std::uint8_t>& file,
                         const std::string& name,
                         std::uint64_t elements,
                         std::uint32_t type, std::uint64_t offset) {
    putString(file,name);
    put32(file,1); put64(file,elements);
    put32(file,type); put64(file,offset);
}
bool writeSyntheticGGUF(const std::filesystem::path& path,
                        const std::vector<std::uint8_t>& embedding,
                        const std::vector<std::uint8_t>& projection,
                        const std::vector<std::uint8_t>& output,
                        const std::vector<std::uint8_t>& f32Norm,
                        const std::vector<std::uint8_t>& f16Norm) {
    std::vector<std::uint8_t> file;
    put32(file,0x46554747u); // "GGUF" little-endian
    put32(file,3);            // GGUF v3
    put64(file,5);            // embedding, attention projection, output head, F32/F16 norms
    put64(file,0);            // metadata count

    putTensorDescriptor(file,"token_embd.weight",32,64,2,0);
    putTensorDescriptor(file,"blk.0.attn_q.weight",32,64,2,embedding.size());
    putTensorDescriptor(file,"output.weight",64,64,2,embedding.size()+projection.size());
    putVectorDescriptor(file,"output_norm.weight",64,0,
                        embedding.size()+projection.size()+output.size());
    putVectorDescriptor(file,"blk.0.attn_norm.weight",64,1,
                        embedding.size()+projection.size()+output.size()+f32Norm.size());

    align32(file);
    if (file.size()%32 || embedding.size()%32 || projection.size()%32 ||
        output.size()%32 || f32Norm.size()%32 || f16Norm.size()%32) return false;
    file.insert(file.end(),embedding.begin(),embedding.end());
    file.insert(file.end(),projection.begin(),projection.end());
    file.insert(file.end(),output.begin(),output.end());
    file.insert(file.end(),f32Norm.begin(),f32Norm.end());
    file.insert(file.end(),f16Norm.begin(),f16Norm.end());

    std::ofstream outFile(path,std::ios::binary|std::ios::trunc);
    if(!outFile) return false;
    outFile.write(reinterpret_cast<const char*>(file.data()),
                  static_cast<std::streamsize>(file.size()));
    return outFile.good();
}
struct DirectReader {
    const std::vector<std::uint8_t>& bytes;
    std::size_t size() const { return bytes.size(); }
    void read(std::size_t offset,std::uint8_t* out,std::size_t count) const {
        if(offset>bytes.size()||count>bytes.size()-offset)
            throw std::out_of_range("direct GGUF fixture range");
        std::memcpy(out,bytes.data()+offset,count);
    }
};
}

int main() {
    constexpr std::size_t vocab=64, hidden=64, embeddingWidth=32;
    const auto embedding=makeQ4ModelTensor(vocab,embeddingWidth);
    const auto projection=makeQ4ModelTensor(hidden,embeddingWidth);
    const auto outputWeights=makeQ4ModelTensor(vocab,hidden);
    std::vector<float> f32NormValues(hidden,1.0f);
    std::vector<std::uint8_t> f32Norm(f32NormValues.size()*sizeof(float));
    std::memcpy(f32Norm.data(),f32NormValues.data(),f32Norm.size());
    std::vector<std::uint16_t> f16NormValues(hidden,0x3c00u);
    std::vector<std::uint8_t> f16Norm(f16NormValues.size()*sizeof(std::uint16_t));
    std::memcpy(f16Norm.data(),f16NormValues.data(),f16Norm.size());
    const auto path=std::filesystem::temp_directory_path()/
        "rawrxd_synthetic_compressed_model_e2e.gguf";
    REQUIRE(writeSyntheticGGUF(path,embedding,projection,outputWeights,f32Norm,f16Norm));

    Deep2::GGUFLoader loader;
    REQUIRE(loader.load(path.string()));
    REQUIRE(loader.loaded());
    REQUIRE(loader.version()==3);
    REQUIRE(loader.tensorCount()==5);
    const auto* mappedEmbedding=loader.getTensor("token_embd.weight");
    const auto* mappedProjection=loader.getTensor("blk.0.attn_q.weight");
    const auto* mappedOutput=loader.getTensor("output.weight");
    const auto* mappedF32Norm=loader.getTensor("output_norm.weight");
    const auto* mappedF16Norm=loader.getTensor("blk.0.attn_norm.weight");
    REQUIRE(mappedEmbedding&&mappedProjection&&mappedOutput&&mappedF32Norm&&mappedF16Norm);
    REQUIRE(mappedEmbedding->mapped&&mappedProjection->mapped&&mappedOutput->mapped&&
            mappedF32Norm->mapped&&mappedF16Norm->mapped);
    REQUIRE(mappedEmbedding->sizeBytes==embedding.size());
    REQUIRE(mappedProjection->sizeBytes==projection.size());
    REQUIRE(mappedOutput->sizeBytes==outputWeights.size());
    REQUIRE(mappedF32Norm->sizeBytes==f32Norm.size());
    REQUIRE(mappedF16Norm->sizeBytes==f16Norm.size());
    REQUIRE(static_cast<std::uint32_t>(mappedProjection->type)==2u);

    // Production mapped-GGUF adapter: ingest the complete synthetic model.
    rawrxd::compression::CompressedWeightStore store(0,64,1u<<20);
    std::string failedTensor,error;
    const auto admitted=rawrxd::compression::StoreMappedGGUFModel(
        store,loader,&failedTensor,&error,true);
    REQUIRE(admitted==5);
    REQUIRE(failedTensor.empty());
    const auto admittedStats=store.stats();
    REQUIRE(admittedStats.tensors==5);
    REQUIRE(admittedStats.raw_bytes==embedding.size()+projection.size()+outputWeights.size()+
                                  f32Norm.size()+f16Norm.size());
    REQUIRE(admittedStats.compressed_bytes<admittedStats.raw_bytes);
    REQUIRE(store.tensorType("blk.0.attn_q.weight")==2u);
    REQUIRE(store.tensorType("output.weight")==2u);
    REQUIRE(store.tensorType("token_embd.weight")==2u);
    REQUIRE(store.tensorType("output_norm.weight")==0u);
    REQUIRE(store.tensorType("blk.0.attn_norm.weight")==1u);

    std::vector<std::uint8_t> normPrefix(16*sizeof(float));
    REQUIRE(store.readRange("output_norm.weight",0,normPrefix.data(),normPrefix.size(),&error));
    REQUIRE(std::memcmp(normPrefix.data(),f32Norm.data(),normPrefix.size())==0);
    std::vector<std::uint8_t> qkNormPrefix(16*sizeof(std::uint16_t));
    REQUIRE(store.readRange("blk.0.attn_norm.weight",0,qkNormPrefix.data(),
                            qkNormPrefix.size(),&error));
    REQUIRE(std::memcmp(qkNormPrefix.data(),f16Norm.data(),qkNormPrefix.size())==0);

    // Release the original GGUF mmap before any inference. All following
    // operations must succeed solely from the compressed resident store.
    loader.close();
    REQUIRE(!loader.loaded());

    using namespace rawrxd::compression;
    constexpr std::size_t token=37;
    std::vector<float> hiddenState(embeddingWidth);
    StoredTensorReadRow(store,"token_embd.weight",ResidentWeightType::Q4_0,
                        token,hiddenState.data(),embeddingWidth);
    for(std::size_t i=0;i<embeddingWidth;++i)
        REQUIRE(hiddenState[i]==(i<16?0.0f:1.0f));

    // One synthetic transformer projection, then the vocabulary output head.
    std::vector<float> qOutput(hidden),qReference(hidden);
    StoredTensorMatvec(store,"blk.0.attn_q.weight",ResidentWeightType::Q4_0,
                       hiddenState.data(),qOutput.data(),hidden,embeddingWidth,7);
    DirectReader directProjection{projection};
    ResidentMatvec(directProjection,ResidentWeightType::Q4_0,
                   hiddenState.data(),qReference.data(),hidden,embeddingWidth,7);
    REQUIRE(qOutput==qReference);
    for(float value:qOutput) REQUIRE(value==16.0f);

    std::vector<float> logits(vocab),referenceLogits(vocab);
    StoredTensorMatvec(store,"output.weight",ResidentWeightType::Q4_0,
                       qOutput.data(),logits.data(),vocab,hidden,7);
    DirectReader directOutput{outputWeights};
    ResidentMatvec(directOutput,ResidentWeightType::Q4_0,
                   qOutput.data(),referenceLogits.data(),vocab,hidden,7);
    REQUIRE(logits==referenceLogits);
    for(float value:logits) REQUIRE(value==512.0f);

    // Greedy token selection is deterministic for the synthetic tied-logit
    // model. The point is to complete the loader->embedding->projection->logits
    // path using compressed-resident tensors, not to claim language quality.
    const std::size_t nextToken=static_cast<std::size_t>(
        std::max_element(logits.begin(),logits.end())-logits.begin());
    REQUIRE(nextToken==0);

    // Selected embedding row is still individually addressable in packed form.
    constexpr std::size_t embeddingRowBytes=(embeddingWidth/32)*18;
    std::array<std::uint8_t,embeddingRowBytes> packedRow{};
    REQUIRE(store.readRange("token_embd.weight",token*embeddingRowBytes,
                            packedRow.data(),packedRow.size(),&error));
    REQUIRE(std::equal(packedRow.begin(),packedRow.end(),
                       embedding.begin()+token*embeddingRowBytes));

    const auto finalStats=store.stats();
    REQUIRE(finalStats.cache_misses>0);
    REQUIRE(finalStats.cached_decoded_bytes==0);
    REQUIRE(finalStats.compressed_bytes<finalStats.raw_bytes);

    // A truncated synthetic model must be rejected by the production parser.
    const auto badPath=path.string()+".truncated";
    {
        std::ifstream in(path,std::ios::binary);
        const std::istreambuf_iterator<char> begin(in);
        const std::istreambuf_iterator<char> end;
        std::vector<char> bytes(begin,end);
        REQUIRE(bytes.size()>64);
        bytes.resize(bytes.size()-17);
        std::ofstream outFile(badPath,std::ios::binary|std::ios::trunc);
        REQUIRE(static_cast<bool>(outFile));
        outFile.write(bytes.data(),static_cast<std::streamsize>(bytes.size()));
        REQUIRE(outFile.good());
    }
    Deep2::GGUFLoader badLoader;
    REQUIRE(!badLoader.load(badPath));
    REQUIRE(!badLoader.error().empty());

    std::error_code ignored;
    std::filesystem::remove(path,ignored);
    std::filesystem::remove(badPath,ignored);
    std::cout<<"SYNTHETIC_GGUF_MODEL_E2E_PASS tensors="<<finalStats.tensors
             <<" raw="<<finalStats.raw_bytes
             <<" compressed="<<finalStats.compressed_bytes
             <<" cache_misses="<<finalStats.cache_misses
             <<" decoded_cache="<<finalStats.cached_decoded_bytes
             <<" next_token="<<nextToken<<" logits="<<logits[0]<<"\n";
    return 0;
}
