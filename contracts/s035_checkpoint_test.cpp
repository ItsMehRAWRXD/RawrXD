// s035_checkpoint_test.cpp — CPU test: checkpoint-content identity across shards.
#include "reap/ReapSelectionIdentity.hpp"
#include <cstdio>
#include <vector>
using namespace RawrXD::Reap;
static int fails = 0;
static void ck(bool ok, const char* n) { std::printf("%s %s\n", ok ? "OK" : "FAIL", n); if (!ok) ++fails; }
int main() {
    std::vector<uint64_t> shards = {111, 222, 333};
    uint64_t id1 = CheckpointContentIdentity(shards, 1000, 32);
    uint64_t id2 = CheckpointContentIdentity(shards, 1000, 32);
    ck(id1 == id2, "deterministic");
    std::vector<uint64_t> shards2 = {111, 222, 999};   // one shard content differs
    ck(CheckpointContentIdentity(shards2, 1000, 32) != id1, "shard_content_differs");
    ck(CheckpointContentIdentity(shards, 1001, 32) != id1, "tensor_count_differs");
    ck(CheckpointContentIdentity(shards, 1000, 64) != id1, "quant_differs");
    std::printf("FAILS=%d\nS035_CHECKPOINT=%s\n", fails, fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}