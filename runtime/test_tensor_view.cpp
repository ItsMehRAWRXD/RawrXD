// ============================================================================
// TensorView Test - Verify GGUF tensor binding and dequantization
// ============================================================================

#include "gguf_reader.hpp"
#include "model_context.hpp"
#include <iostream>
#include <iomanip>
#include <cstring>

using namespace RawrXD::Runtime;

void PrintUsage(const char* program) {
    std::cout << "Usage: " << program << " <gguf_file>" << std::endl;
    std::cout << "       " << program << " --synthetic" << std::endl;
}

void PrintProvenance(const TensorProvenance* prov) {
    if (!prov) {
        std::cout << "  Provenance: NULL" << std::endl;
        return;
    }
    
    std::cout << "  Provenance:" << std::endl;
    std::cout << "    Source: " << prov->source << std::endl;
    std::cout << "    Tensor: " << prov->tensorName << std::endl;
    std::cout << "    Offset: " << prov->byteOffset << std::endl;
    std::cout << "    Bytes: " << prov->bytes << std::endl;
    std::cout << "    Quantized: " << (prov->quantized ? "yes" : "no") << std::endl;
    std::cout << "    Synthetic: " << (prov->IsSynthetic() ? "yes" : "no") << std::endl;
}

float ComputeChecksum(const float* data, size_t count) {
    float sum = 0.0f;
    for (size_t i = 0; i < count; ++i) {
        sum += data[i] * (i + 1);  // Weighted sum
    }
    return sum;
}

int main(int argc, char* argv[]) {
    std::cout << "=== TensorView Test ===" << std::endl;
    std::cout << std::endl;
    
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    std::string path = argv[1];
    bool synthetic = (path == "--synthetic");
    
    if (synthetic) {
        std::cout << "Mode: Synthetic Model" << std::endl;
        path = "nonexistent.gguf";
    } else {
        std::cout << "Mode: GGUF File" << std::endl;
        std::cout << "Path: " << path << std::endl;
    }
    
    std::cout << std::endl;
    
    // Test 1: ModelContext with TensorView
    std::cout << "--- Test 1: ModelContext with TensorView ---" << std::endl;
    
    ModelContext context;
    if (!ModelContext::LoadFromGGUF(path, context)) {
        std::cout << "✗ Failed to load ModelContext" << std::endl;
        return 1;
    }
    
    std::cout << "✓ ModelContext loaded" << std::endl;
    std::cout << "  Using real weights: " << (context.IsUsingRealWeights() ? "yes" : "no") << std::endl;
    std::cout << "  Source: " << context.GetWeightSource() << std::endl;
    std::cout << "  Vocab: " << context.VocabSize() << std::endl;
    std::cout << "  Hidden: " << context.HiddenSize() << std::endl;
    
    // Test 2: TensorView access
    std::cout << std::endl;
    std::cout << "--- Test 2: TensorView Access ---" << std::endl;
    
    TensorView tokenEmbView = context.GetTensorView("token_embd.weight");
    if (tokenEmbView.IsValid()) {
        std::cout << "✓ Token embeddings view valid" << std::endl;
        std::cout << "  Rows: " << tokenEmbView.Rows() << std::endl;
        std::cout << "  Cols: " << tokenEmbView.Cols() << std::endl;
        std::cout << "  Type: " << static_cast<int>(tokenEmbView.Type()) << std::endl;
        std::cout << "  IsQuantized: " << (tokenEmbView.IsQuantized() ? "yes" : "no") << std::endl;
        std::cout << "  IsSynthetic: " << (tokenEmbView.IsSynthetic() ? "yes" : "no") << std::endl;
        
        PrintProvenance(tokenEmbView.GetProvenance());
        
        // Test dequantization of first row
        std::vector<float> rowData(tokenEmbView.Cols());
        size_t dequantized = tokenEmbView.DequantizeRow(0, rowData.data(), rowData.size());
        std::cout << "  Dequantized row 0: " << dequantized << " elements" << std::endl;
        
        if (dequantized > 0) {
            float checksum = ComputeChecksum(rowData.data(), dequantized);
            std::cout << "  Row checksum: " << std::fixed << std::setprecision(6) << checksum << std::endl;
        }
    } else {
        std::cout << "✗ Token embeddings view invalid" << std::endl;
    }
    
    // Test 3: Output weight
    std::cout << std::endl;
    std::cout << "--- Test 3: Output Weight ---" << std::endl;
    
    TensorView outputView = context.GetTensorView("output.weight");
    if (outputView.IsValid()) {
        std::cout << "✓ Output weight view valid" << std::endl;
        std::cout << "  Rows: " << outputView.Rows() << std::endl;
        std::cout << "  Cols: " << outputView.Cols() << std::endl;
        PrintProvenance(outputView.GetProvenance());
    } else {
        std::cout << "✗ Output weight view invalid" << std::endl;
    }
    
    // Test 4: Norm weight
    std::cout << std::endl;
    std::cout << "--- Test 4: Norm Weight ---" << std::endl;
    
    TensorView normView = context.GetTensorView("output_norm.weight");
    if (normView.IsValid()) {
        std::cout << "✓ Norm weight view valid" << std::endl;
        std::cout << "  Rows: " << normView.Rows() << std::endl;
        std::cout << "  Cols: " << normView.Cols() << std::endl;
        PrintProvenance(normView.GetProvenance());
    } else {
        std::cout << "✗ Norm weight view invalid" << std::endl;
    }
    
    // Test 5: Compare checksums (synthetic vs real)
    std::cout << std::endl;
    std::cout << "--- Test 5: Embedding Checksum Comparison ---" << std::endl;
    
    // Always load synthetic for comparison
    ModelContext syntheticContext;
    ModelContext::LoadFromGGUF("nonexistent.gguf", syntheticContext);
    
    TensorView syntheticEmb = syntheticContext.GetTensorView("token_embd.weight");
    if (syntheticEmb.IsValid() && tokenEmbView.IsValid()) {
        std::vector<float> synRow(syntheticEmb.Cols());
        std::vector<float> realRow(tokenEmbView.Cols());
        
        syntheticEmb.DequantizeRow(77, synRow.data(), synRow.size());
        tokenEmbView.DequantizeRow(77, realRow.data(), realRow.size());
        
        float synChecksum = ComputeChecksum(synRow.data(), synRow.size());
        float realChecksum = ComputeChecksum(realRow.data(), realRow.size());
        
        std::cout << "Token 77 embedding checksum:" << std::endl;
        std::cout << "  Synthetic: " << std::fixed << std::setprecision(6) << synChecksum << std::endl;
        std::cout << "  Real:      " << std::fixed << std::setprecision(6) << realChecksum << std::endl;
        
        if (synChecksum != realChecksum) {
            std::cout << "  ✓ Checksums differ (real vs synthetic)" << std::endl;
        } else {
            std::cout << "  ⚠ Checksums match (unexpected)" << std::endl;
        }
    }
    
    std::cout << std::endl;
    std::cout << "=== Test Complete ===" << std::endl;
    
    return 0;
}
