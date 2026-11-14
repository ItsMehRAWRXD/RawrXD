                        create_tensor_gate_up_exps(layer, i, n_embd, n_ff_exp, n_expert, 0);

                        // Shared experts
                        const int64_t n_ff_shexp = hparams.n_ff_shexp ? hparams.n_ff_shexp : n_ff;

                        layer.ffn_gate_inp_shexp = create_tensor(tn(LLM_TENSOR_FFN_GATE_INP_SHEXP, "weight", i), { n_embd }, 0);
                        layer.ffn_gate_shexp     = create_tensor(tn(LLM_TENSOR_FFN_GATE_SHEXP,     "weight", i), { n_embd, n_ff_shexp }, 0);
                        layer.ffn_up_shexp       = create_tensor(tn(LLM_TENSOR_FFN_UP_SHEXP,       "weight", i), { n_embd, n_ff_shexp }, 0);
                        layer.ffn_down_shexp     = create_tensor(tn(LLM_TENSOR_FFN_DOWN_SHEXP,     "weight", i), { n_ff_shexp, n_embd }, 0);

                        // NextN/MTP tensors on last nextn_predict_layers (Ornith: blk.40.nextn.*)
                        // TENSOR_SKIP: count for done_getting_tensors; unused in graph; no fabricate.
                        if (hparams.nextn_predict_layers > 0 &&
                            static_cast<uint32_t>(i) >= static_cast<uint32_t>(n_layer) - hparams.nextn_predict_layers) {
                            const int nflags = TENSOR_SKIP;
                            layer.nextn.eh_proj          = create_tensor(tn(LLM_TENSOR_NEXTN_EH_PROJ, "weight", i), { 2 * n_embd, n_embd }, nflags);
                            layer.nextn.enorm            = create_tensor(tn(LLM_TENSOR_NEXTN_ENORM, "weight", i), { n_embd }, nflags);
                            layer.nextn.hnorm            = create_tensor(tn(LLM_TENSOR_NEXTN_HNORM, "weight", i), { n_embd }, nflags);
                            layer.nextn.embed_tokens     = create_tensor(tn(LLM_TENSOR_NEXTN_EMBED_TOKENS, "weight", i), { n_embd, n_vocab }, nflags | TENSOR_NOT_REQUIRED);
                            layer.nextn.shared_head_head = create_tensor(tn(LLM_TENSOR_NEXTN_SHARED_HEAD_HEAD, "weight", i), { n_embd, n_vocab }, nflags | TENSOR_NOT_REQUIRED);
                            layer.nextn.shared_head_norm = create_tensor(tn(LLM_TENSOR_NEXTN_SHARED_HEAD_NORM, "weight", i), { n_embd }, nflags | TENSOR_NOT_REQUIRED);
