// Dummy implementation of BlockedGemm_CPP for testing
extern "C" void BlockedGemm_CPP(float* A, float* B, float* C, int M, int N, int K, float alpha, float beta) {
    // Simple dummy implementation: just set output to 1.0
    for (int i = 0; i < M * N; i++) {
        C[i] = 1.0f;
    }
}