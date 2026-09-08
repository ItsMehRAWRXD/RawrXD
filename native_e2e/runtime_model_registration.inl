/*
Call after REAL GGUF metadata/topology has been resolved and before the model
is exposed through /models or /api/tags.

RawrNativeProfileInfo p{};
p.profile_id      = yourStableRuntimeModelId;
p.engine_mode     = actualEngineModeFlags;  // SAFEDECODE/TENSORHOP only if supported
p.num_layers      = metadata.numLayers;
p.context_default = configuredDefaultContext;
p.context_max     = metadata.maxContextOrRuntimeLimit;
p.max_tokens      = configuredMaxOutputTokens;
p.tier            = resolvedTier;
p.quant_type      = resolvedQuantType;
p.ram_mb          = measuredOrPlannedRamMiB;
p.vram_mb         = measuredOrPlannedVramMiB;

RawrNative_RegisterRuntimeModel(exactModelName.c_str(), &p);

On unload:
RawrNative_UnregisterRuntimeModel(exactModelName.c_str());

For Kimi-K2 and the 11-shard DeepSeek-R1 this runtime registration should be
the authority. Do not force them into a similarly-named static 8B/70B profile.
*/
