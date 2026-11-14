#include <cstdio>
#include <cstdlib>
#include <vector>
#include <filesystem>
#include "llama.h"
int main(int argc, char** argv) {
  if (argc < 4) { std::fprintf(stderr, "Usage: %s model tokens_file out_dir\n", argv[0]); return 1; }
  FILE* tf = std::fopen(argv[2], "r");
  std::vector<llama_token> toks; int t;
  while (std::fscanf(tf, "%d", &t) == 1) toks.push_back(t);
  std::fclose(tf);
  llama_backend_init();
  auto mp = llama_model_default_params(); mp.n_gpu_layers = 0;
  llama_model* model = llama_model_load_from_file(argv[1], mp);
  if (!model) return 2;
  auto cp = llama_context_default_params();
  cp.n_ctx = 1024; cp.n_batch = (int32_t)toks.size(); cp.n_ubatch = (int32_t)toks.size();
  llama_context* ctx = llama_init_from_model(model, cp);
  if (!ctx) return 3;
  std::filesystem::create_directories(argv[3]);
  llama_batch batch = llama_batch_init((int32_t)toks.size(), 0, 1);
  batch.n_tokens = (int32_t)toks.size();
  for (int i = 0; i < batch.n_tokens; ++i) {
    batch.token[i] = toks[i];
    batch.pos[i] = i;
    batch.n_seq_id[i] = 1;
    batch.seq_id[i][0] = 0;
    batch.logits[i] = (i + 1 == batch.n_tokens);
  }
  if (llama_decode(ctx, batch) != 0) { std::fprintf(stderr, "decode fail\n"); return 4; }
  float* logits = llama_get_logits_ith(ctx, batch.n_tokens - 1);
  const llama_vocab* vocab = llama_model_get_vocab(model);
  int n = llama_vocab_n_tokens(vocab);
  char path[512];
  std::snprintf(path, sizeof(path), "%s/ref_logits_batched_last.bin", argv[3]);
  FILE* o = std::fopen(path, "wb");
  std::fwrite(logits, 4, n, o); std::fclose(o);
  int arg = 0; float best = logits[0];
  for (int i = 1; i < n; ++i) if (logits[i] > best) { best = logits[i]; arg = i; }
  std::printf("BATCHED_LAST n_tok=%d arg=%d max=%.6f\n", batch.n_tokens, arg, best);
  std::printf("15233=%.6f 29213=%.6f margin29213-15233=%.6f\n",
              logits[15233], logits[29213], logits[29213]-logits[15233]);
  llama_batch_free(batch); llama_free(ctx); llama_model_free(model); llama_backend_free();
  return 0;
}
