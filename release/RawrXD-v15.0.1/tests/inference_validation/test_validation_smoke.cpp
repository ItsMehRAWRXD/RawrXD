/**
 * Validation Framework Smoke Test
 * Tests that the validation hooks work correctly
 */

#include <cstdio>
#include <cstring>
#include <vector>
#include <cmath>

// Include the runtime hooks
#include "harness/runtime_hooks.hpp"
#include "harness/reference_loader.hpp"
#include "harness/tensor_compare.hpp"

using namespace rawrxd::validation;

bool test_validation_hooks() {
    printf("Testing validation hooks...\n");
    
    // Initialize validation
    RAWRXD_VALIDATION_INIT("test_output.bin");
    
    // Simulate layer outputs
    std::vector<float> rms_norm(4096, 1.0f);
    std::vector<float> attn_out(4096, 0.5f);
    std::vector<float> ffn_out(4096, 0.25f);
    std::vector<float> logits(32000, 0.01f);
    
    // Dump tensors
    RAWRXD_VALIDATION_DUMP_RMS_NORM(rms_norm.data(), rms_norm.size(), 0);
    RAWRXD_VALIDATION_DUMP_ATTN_OUT(attn_out.data(), attn_out.size(), 0);
    RAWRXD_VALIDATION_DUMP_FFN(ffn_out.data(), ffn_out.size(), 0);
    RAWRXD_VALIDATION_DUMP_LOGITS(logits.data(), logits.size());
    
    // Close
    RAWRXD_VALIDATION_CLOSE();
    
    printf("  Validation hooks: OK\n");
    return true;
}

bool test_reference_loader() {
    printf("Testing reference loader...\n");
    
    ReferenceLoader loader;
    
    // Create a simple test file
    FILE* fp = fopen("test_ref.bin", "wb");
    if (!fp) {
        printf("  Failed to create test file\n");
        return false;
    }
    
    // Write header
    uint32_t magic = 0x52414452; // "RADR"
    uint32_t version = 1;
    fwrite(&magic, sizeof(magic), 1, fp);
    fwrite(&version, sizeof(version), 1, fp);
    
    // Write a test tensor
    int layer = 0;
    uint16_t name_len = 8;
    const char* name = "rms_norm";
    int n_dims = 1;
    int shape = 4096;
    size_t n_elements = 4096;
    
    fwrite(&layer, sizeof(layer), 1, fp);
    fwrite(&name_len, sizeof(name_len), 1, fp);
    fwrite(name, 1, name_len, fp);
    fwrite(&n_dims, sizeof(n_dims), 1, fp);
    fwrite(&shape, sizeof(shape), 1, fp);
    fwrite(&n_elements, sizeof(n_elements), 1, fp);
    
    // Write data
    std::vector<float> data(4096, 1.0f);
    fwrite(data.data(), sizeof(float), n_elements, fp);
    
    fclose(fp);
    
    // Load and verify
    if (!loader.load("test_ref.bin")) {
        printf("  Failed to load reference file\n");
        return false;
    }
    
    if (loader.getRecordCount() != 1) {
        printf("  Expected 1 record, got %zu\n", loader.getRecordCount());
        return false;
    }
    
    const TensorRecord* rec = loader.findTensor("rms_norm", 0);
    if (!rec) {
        printf("  Failed to find tensor\n");
        return false;
    }
    
    printf("  Reference loader: OK\n");
    return true;
}

bool test_tensor_compare() {
    printf("Testing tensor comparison...\n");
    
    std::vector<float> expected(4096);
    std::vector<float> actual(4096);
    
    // Fill with same values
    for (size_t i = 0; i < 4096; i++) {
        expected[i] = static_cast<float>(i) * 0.001f;
        actual[i] = expected[i];
    }
    
    // Compare
    TensorComparison result = compareTensor(expected.data(), actual.data(), 4096, 1e-5f);
    
    if (!result.passed) {
        printf("  Expected pass for identical tensors\n");
        return false;
    }
    
    // Add some error
    actual[100] += 0.01f;
    result = compareTensor(expected.data(), actual.data(), 4096, 1e-5f);
    
    if (result.passed) {
        printf("  Expected fail for different tensors\n");
        return false;
    }
    
    printf("  Tensor comparison: OK\n");
    return true;
}

int main() {
    printf("\n=================================\n");
    printf("RawrXD Validation Framework Smoke Test\n");
    printf("=================================\n\n");
    
    int passed = 0;
    int failed = 0;
    
    if (test_validation_hooks()) passed++; else failed++;
    if (test_reference_loader()) passed++; else failed++;
    if (test_tensor_compare()) passed++; else failed++;
    
    printf("\n=================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);
    printf("=================================\n\n");
    
    return failed > 0 ? 1 : 0;
}
