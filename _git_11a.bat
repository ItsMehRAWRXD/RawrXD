@echo off
cd /d F:\
git add ~dev/rawrxd/src/deep2/Deep2DualGpuRowSplit.cpp 2> nul
git commit -m "Batch 11A — Fix adaptive column-cache replacement path in q4kColumnSlices()

Replace the broken duplicate-key emplace path (which performed a self-move
and then re-used a moved-from local) with a clean try_emplace + move pattern.

- ONE_CACHE_ENTRY_PER_WEIGHT=1
- RATIO_CHANGE_REPLACES_ENTRY=1
- OLD_SPLIT_RELEASED=1
- MOVED_FROM_COPY=0
- CACHE_GROWTH_AFTER_WARMUP=0" 2> nul
git push 2> nul
git log origin/main -1 --oneline > f:\~dev\_git_11a_verify.txt 2> nul
