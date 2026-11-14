                }
            } break;
        case LLM_ARCH_QWEN35MOE:
            {
                ml.get_key(LLM_KV_EXPERT_FEED_FORWARD_LENGTH,        hparams.n_ff_exp, false);
                ml.get_key(LLM_KV_EXPERT_SHARED_FEED_FORWARD_LENGTH, hparams.n_ff_shexp, false);
                ml.get_key(LLM_KV_ATTENTION_LAYERNORM_RMS_EPS,       hparams.f_norm_rms_eps);
                ml.get_key(LLM_KV_NEXTN_PREDICT_LAYERS,              hparams.nextn_predict_layers, false);

                ml.get_key_or_arr(LLM_KV_ROPE_DIMENSION_SECTIONS,    hparams.rope_sections, 4, true);

                // Load linear attention (gated delta net) parameters
                ml.get_key(LLM_KV_SSM_CONV_KERNEL,    hparams.ssm_d_conv);
                ml.get_key(LLM_KV_SSM_INNER_SIZE,     hparams.ssm_d_inner);
                ml.get_key(LLM_KV_SSM_STATE_SIZE,     hparams.ssm_d_state);
                ml.get_key(LLM_KV_SSM_TIME_STEP_RANK, hparams.ssm_dt_rank);
                ml.get_key(LLM_KV_SSM_GROUP_COUNT,    hparams.ssm_n_group);

                // MTP/NextN (Ornith REAP194: qwen35moe.nextn_predict_layers=1).
                // Load+SKIP nextn tensors only; do not shrink the main layer stack.
                ml.get_key(LLM_KV_NEXTN_PREDICT_LAYERS, hparams.nextn_predict_layers, false);

                // Mark recurrent layers (linear attention layers)
                {
                    uint32_t full_attn_interval = 4;
                    ml.get_key(LLM_KV_FULL_ATTENTION_INTERVAL, full_attn_interval, false);
                    for (uint32_t i = 0; i < hparams.n_layer; ++i) {
                        hparams.recurrent_layer_arr[i] = ((i + 1) % full_attn_interval != 0);
                    }
                    // Ornith REAP194 / hybrid MoE: final block (e.g. blk.40) is full-attn + nextn,
                    // not SSM. Interval formula alone would require missing blk.N.ssm_conv1d.weight.
                    // ABSENT_NOT_RENAME — probe GGUF; do not fabricate tensors.
                    for (uint32_t i = 0; i < hparams.n_layer; ++i) {
                        if (!hparams.recurrent_layer_arr[i]) {
                            continue;
                        }
                        const std::string ssm_name  = "blk." + std::to_string(i) + ".ssm_conv1d.weight";
                        const std::string attn_name = "blk." + std::to_string(i) + ".attn_q.weight";
                        if (ml.get_tensor_meta(ssm_name.c_str()) == nullptr &&
                            ml.get_tensor_meta(attn_name.c_str()) != nullptr) {
                            hparams.recurrent_layer_arr[i] = false;
                            LLAMA_LOG_INFO("%s: qwen35moe hybrid: layer %u formula=recurrent but ssm_conv1d ABSENT + attn_q PRESENT → full-attn (no fabricate)\n",
                                           __func__, i);
                        }
                    }
                }

                switch (hparams.n_layer) {
                    case 40: type = LLM_TYPE_35B_A3B; break;
                    case 48: type = LLM_TYPE_122B_A10B; break;
                    case 60: type = LLM_TYPE_397B_A17B; break;
                    default: type = LLM_TYPE_UNKNOWN;
                }
            } break;
        case LLM_ARCH_MISTRAL3:
            {
                ml.get_key(LLM_KV_ATTENTION_LAYERNORM_RMS_EPS, hparams.f_norm_rms_eps);
                ml.get_key(LLM_KV_ATTENTION_TEMPERATURE_SCALE, hparams.f_attn_temp_scale, false);
