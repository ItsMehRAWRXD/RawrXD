from pathlib import Path
path = Path(r"F:\rawrxd\src\deep2\Deep2Engine.cpp")
text = path.read_text(encoding="utf-8")
old = """        gguf_shard_cache::TensorResidencyCache::Config residencyConfig;
        residencyConfig.max_active = 1024;
        if (reapRuntimeInjection_.enabled)
        {
            if (reapRuntimeInjection_.workingSetBytes >
                static_cast<uint64_t>((std::numeric_limits<size_t>::max)()))
            {
                fitRejectReason_ = \"runtime working-set target does not fit host size type\";
                reapRuntimeReceipt_.status = \"TARGET_OVERFLOW\";
                reapRuntimeReceipt_.reason = \"WORKING_SET_EXCEEDS_HOST_SIZE_T\";
                return false;
            }
            residencyConfig.max_resident_bytes =
                static_cast<uint64_t>(reapRuntimeInjection_.workingSetBytes);
        }
        residencyCache_ = std::make_unique<gguf_shard_cache::TensorResidencyCache>(residencyConfig);
"""
new = """        gguf_shard_cache::TensorResidencyCache::Config residencyConfig;
        residencyConfig.max_active = 1024;
        if (reapRuntimeInjection_.enabled)
        {
            if (reapRuntimeInjection_.workingSetBytes >
                static_cast<uint64_t>((std::numeric_limits<size_t>::max)()))
            {
                fitRejectReason_ = \"runtime working-set target does not fit host size type\";
                reapRuntimeReceipt_.status = \"TARGET_OVERFLOW\";
                reapRuntimeReceipt_.reason = \"WORKING_SET_EXCEEDS_HOST_SIZE_T\";
                return false;
            }
            residencyConfig.max_resident_bytes =
                static_cast<uint64_t>(reapRuntimeInjection_.workingSetBytes);
        }
        // MiniMax standard multi-shard pins non-expert attn/norm/router for the
        // whole generation. REAP expert working-set must not starve those pins.
        {
            std::string archLower = k2config.architecture;
            std::transform(archLower.begin(), archLower.end(), archLower.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (archLower.find(\"minimax\") != std::string::npos)
            {
                uint64_t nonExpertBytes = 0;
                globalIndex_->ForEach([&](const GlobalTensorRef& ref) {
                    if (!ref.isExpertTensor)
                        nonExpertBytes += ref.byteSize;
                });
                constexpr uint64_t kGranule = 65536ull;
                const uint64_t pinFloor =
                    nonExpertBytes +
                    kGranule * static_cast<uint64_t>(residencyConfig.max_active);
                const uint64_t expertBudget = residencyConfig.max_resident_bytes;
                const uint64_t need =
                    (expertBudget > 0 &&
                     pinFloor <= (std::numeric_limits<uint64_t>::max)() - expertBudget)
                        ? (pinFloor + expertBudget)
                        : pinFloor;
                if (need > 0 &&
                    (residencyConfig.max_resident_bytes == 0 ||
                     residencyConfig.max_resident_bytes < need))
                {
                    std::fprintf(stderr,
                                 \"[MULTISHARD_RESIDENCY] minimax pin floor \"
                                 \"from=%llu to=%llu non_expert=%llu expert_budget=%llu\\n\",
                                 static_cast<unsigned long long>(
                                     residencyConfig.max_resident_bytes),
                                 static_cast<unsigned long long>(need),
                                 static_cast<unsigned long long>(nonExpertBytes),
                                 static_cast<unsigned long long>(expertBudget));
                    std::fflush(stderr);
                    residencyConfig.max_resident_bytes = need;
                }
            }
        }
        residencyCache_ = std::make_unique<gguf_shard_cache::TensorResidencyCache>(residencyConfig);
"""
# Fix escapes - the old/new above used escaped quotes for python string; use raw
old = old.replace('\\"', '"')
new = new.replace('\\"', '"')
if old not in text:
    raise SystemExit("OLD_BLOCK_NOT_FOUND")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
print("PATCH_OK")
