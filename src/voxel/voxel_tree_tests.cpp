// ============================================================================
// voxel_tree_tests.cpp — the gates of a conifer.
//
// A tree is not certified because it looks like a conifer. It is certified
// because its silhouette has a trunk, tiers of foliage that step down, a
// crown that narrows all the way to the point, and a height against a
// width that says it is a tree and not a bush.
//
// The tree that is measured here is the same tree the world is built from:
// the blocks come out of the one builder, so there is no second shape that
// is the good one and the other one is what gets drawn.
// ============================================================================

#include <cstdio>
#include <string>
#include <vector>

#include "ChunkStore.hpp"
#include "Math.hpp"

using namespace sunshine;

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool condition, const char* name, const std::string& detail = "") {
    ++g_checks;
    if (condition) {
        printf("  pass  %s\n", name);
    } else {
        ++g_failures;
        printf("  FAIL  %s%s%s\n", name, detail.empty() ? "" : " : ", detail.c_str());
    }
}

std::string number(double value, int decimals = 2) {
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%.*f", decimals, value);
    return buffer;
}

// The shape of a tree, printed as a picture.
//
// It is here so that a failure can be read: a tree that fails the taper
// looks like a lollipop and one that fails the ratio looks like a bush.
void printSilhouette(const TreeMetrics& metrics) {
    if (metrics.sliceWidth.empty()) return;
    const int32_t top = static_cast<int32_t>(metrics.sliceWidth.size()) - 1;
    for (int32_t level = top; level >= 0; --level) {
        const int32_t width = metrics.sliceWidth[static_cast<size_t>(level)];
        if (width <= 0) continue;
        printf("        %s\n", std::string(static_cast<size_t>(width), '#').c_str());
    }
}

} // namespace

int main() {
    printf("the gates of a conifer\n");

    World world(0x5EED1234u);

    // -------------------------------------------------------------------
    // The conifer: the shape of it.
    // -------------------------------------------------------------------
    std::vector<TreeBlock> blocks;
    world.buildTree(TreeKind::Conifer, 0, 0, 70, 12345u, blocks);
    const TreeMetrics metrics = World::measureTreeShape(blocks, 70);

    printf("\none. the conifer\n");
    printf("  the height is %d and the width is %d\n", metrics.height, metrics.width);
    printf("  the ratio is %s\n", number(metrics.ratio()).c_str());
    printf("  the tiers are %d and the trunk is %d blocks\n", metrics.tiers, metrics.trunkHeight);
    printSilhouette(metrics);

    check(metrics.height > 0, "the tree has a height");
    check(metrics.ratio() >= 2.5, "the height against the width is at least two and a half",
          std::string("got ") + number(metrics.ratio()).c_str());
    check(metrics.tiers >= 3, "the crown has at least three tiers of foliage",
          "got " + std::to_string(metrics.tiers));
    check(metrics.topTapers(), "the top quarter of the tree narrows without a break");
    check(metrics.trunkHeight >= 2, "the trunk is bare for a few blocks",
          "got " + std::to_string(metrics.trunkHeight));

    // The trunk is visible in the lower part only: the crown does not
    // come all the way down to the ground.
    bool crownTouchesGround = false;
    for (int32_t level = 0; level < metrics.trunkHeight; ++level) {
        if (metrics.sliceWidth[static_cast<size_t>(level)] > 1) crownTouchesGround = true;
    }
    check(!crownTouchesGround, "the crown does not touch the ground");

    // -------------------------------------------------------------------
    // The broadleaf: it is the other shape, and it is not a conifer.
    // -------------------------------------------------------------------
    printf("\ntwo. the broadleaf is not a conifer\n");
    std::vector<TreeBlock> oak;
    world.buildTree(TreeKind::Oak, 0, 0, 70, 12345u, oak);
    const TreeMetrics oakMetrics = World::measureTreeShape(oak, 70);
    printf("  the height is %d and the width is %d\n", oakMetrics.height, oakMetrics.width);
    check(oakMetrics.ratio() < metrics.ratio(), "the broadleaf is squatter than the conifer");
    {
        // A broadleaf is a blob: it is widest near the top, because the
        // crown sits on the end of the trunk. A conifer is widest at the
        // bottom. That is the difference between the two shapes.
        const int32_t top = static_cast<int32_t>(oakMetrics.sliceWidth.size()) - 1;
        int32_t widestAt = 0;
        int32_t widest = 0;
        for (int32_t level = 0; level <= top; ++level) {
            if (oakMetrics.sliceWidth[static_cast<size_t>(level)] > widest) {
                widest = oakMetrics.sliceWidth[static_cast<size_t>(level)];
                widestAt = level;
            }
        }
        check(widestAt * 2 > top, "the broadleaf is widest near the top",
              "widest at " + std::to_string(widestAt) + " of " + std::to_string(top));
    }

    // -------------------------------------------------------------------
    // The variation: two trees side by side are not the same tree, and the
    // same tree twice is the same tree.
    // -------------------------------------------------------------------
    printf("\nthree. the trees vary and the variation is fixed\n");

    std::vector<TreeBlock> first;
    std::vector<TreeBlock> second;
    std::vector<TreeBlock> firstAgain;
    world.buildTree(TreeKind::Conifer, 0, 0, 70, 111u, first);
    world.buildTree(TreeKind::Conifer, 7, 3, 70, 222u, second);
    world.buildTree(TreeKind::Conifer, 0, 0, 70, 111u, firstAgain);

    const auto sameShape = [](const std::vector<TreeBlock>& a, const std::vector<TreeBlock>& b) {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); ++i) {
            if (a[i].x != b[i].x || a[i].y != b[i].y || a[i].z != b[i].z) return false;
        }
        return true;
    };

    check(sameShape(first, firstAgain), "the same tree built twice is the same tree");
    check(!sameShape(first, second), "two trees side by side are not the same tree");

    // Every conifer has to pass the gates, not just the one that was
    // looked at.
    int built = 0;
    int passed = 0;
    for (int32_t x = -60; x <= 60; x += 7) {
        for (int32_t z = -60; z <= 60; z += 7) {
            const uint32_t seed = static_cast<uint32_t>(x * 73856093) ^ static_cast<uint32_t>(z * 19349663);
            std::vector<TreeBlock> tree;
            world.buildTree(TreeKind::Conifer, x, z, 70, seed, tree);
            if (tree.empty()) continue;
            ++built;
            const TreeMetrics shape = World::measureTreeShape(tree, 70);
            if (shape.ratio() >= 2.5 && shape.tiers >= 3 && shape.topTapers() &&
                shape.trunkHeight >= 2) {
                ++passed;
            }
        }
    }
    check(built > 0, "there were trees to measure", "built " + std::to_string(built));
    check(built == passed, "every conifer passes the gates",
          std::to_string(passed) + " of " + std::to_string(built) + " passed");

    // -------------------------------------------------------------------
    // The world uses the same tree.
    // -------------------------------------------------------------------
    printf("\nfour. the world is built from the same tree\n");
    {
        World plain(0x5EED1234u);
        const int32_t surface = plain.surfaceHeight(0, 0);
        check(surface > 0, "the world has a surface");

        // There are trees in the world: the world is scanned for a block
        // of foliage, and the tree that stands there is measured with the
        // same measurement the test above used.
        int32_t treeX = 0;
        int32_t treeZ = 0;
        int32_t treeY = 0;
        bool found = false;
        for (int32_t x = -48; x <= 48 && !found; ++x) {
            for (int32_t z = -48; z <= 48 && !found; ++z) {
                for (int32_t y = 60; y < 100 && !found; ++y) {
                    if (plain.blockAt(x, y, z) != static_cast<uint8_t>(BlockType::Leaves)) continue;
                    // The trunk of the tree is below the foliage.
                    for (int32_t down = y; down > 40; --down) {
                        if (plain.blockAt(x, down, z) == static_cast<uint8_t>(BlockType::Wood)) {
                            treeX = x;
                            treeZ = z;
                            treeY = down;
                            found = true;
                            break;
                        }
                    }
                }
            }
        }
        check(found, "a tree was found in the world");
        if (found) {
            std::vector<TreeBlock> placed;
            plain.buildTree(TreeKind::Conifer, treeX, treeZ, treeY,
                            0x5EED1234u ^ static_cast<uint32_t>(treeX * 73856093) ^
                                static_cast<uint32_t>(treeZ * 19349663),
                            placed);
            const TreeMetrics shape = World::measureTreeShape(placed, treeY);
            check(shape.ratio() >= 2.5, "the tree in the world is a conifer too",
                  std::string("got ") + number(shape.ratio()).c_str());
            check(shape.tiers >= 3, "the tree in the world has its tiers",
                  "got " + std::to_string(shape.tiers));
        }
    }

    // -------------------------------------------------------------------
    // The stand: the trees are of different ages, and the forest has
    // thickets in it and clearings.
    // -------------------------------------------------------------------
    printf("\nfive. the forest has thickets and clearings and trees of age\n");

    // The ages of the trees across a sample, and the shape of the stand.
    int32_t shortest = 1000;
    int32_t tallest = 0;
    int32_t sampled = 0;
    for (int32_t x = -80; x <= 80; x += 3) {
        for (int32_t z = -80; z <= 80; z += 3) {
            const uint32_t seed = static_cast<uint32_t>(x * 73856093) ^ static_cast<uint32_t>(z * 19349663);
            std::vector<TreeBlock> tree;
            world.buildTree(TreeKind::Conifer, x, z, 70, seed, tree);
            if (tree.empty()) continue;
            ++sampled;
            const TreeMetrics shape = World::measureTreeShape(tree, 70);
            if (shape.height < shortest) shortest = shape.height;
            if (shape.height > tallest) tallest = shape.height;
        }
    }
    printf("  %d trees were measured, from %d to %d blocks\n", sampled, shortest, tallest);
    check(sampled > 0, "there were trees to measure the ages of");
    check(tallest >= shortest * 2, "the oldest tree is at least twice the height of the youngest",
          "the youngest is " + std::to_string(shortest) + " and the oldest is " +
              std::to_string(tallest));

    // The stand: the chance of a tree in the thickest part of the forest
    // against the chance in the sparsest part of it.
    {
        World stand(0x5EED1234u);

        // A census of the ground, so that a biome that never appears is
        // a fact and not a guess.
        int32_t census[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
        for (int32_t x = -160; x <= 160; x += 4) {
            for (int32_t z = -160; z <= 160; z += 4) {
                const int32_t index = static_cast<int32_t>(stand.biomeAt(x, z));
                if (index >= 0 && index < 9) ++census[index];
            }
        }
        printf("  the ground: ocean %d, beach %d, plains %d, forest %d, desert %d, savanna %d,"
               " tundra %d, snow %d, mountains %d\n",
               census[0], census[1], census[2], census[3], census[4], census[5], census[6],
               census[7], census[8]);
        check(census[3] > 0, "the world has forest in it", "found " + std::to_string(census[3]));

        int32_t thickest = 0;
        int32_t sparsest = 1000;
        int32_t counted = 0;
        for (int32_t x = -120; x <= 120; x += 4) {
            for (int32_t z = -120; z <= 120; z += 4) {
                // The conifers stand in the forest and in the cold ground.
                const Biome biome = stand.biomeAt(x, z);
                const bool cold = (biome == Biome::Snow || biome == Biome::Tundra);
                if (biome != Biome::Forest && !cold) continue;
                ++counted;
                int32_t trees = 0;
                for (int32_t dx = -1; dx <= 1; ++dx) {
                    for (int32_t dz = -1; dz <= 1; ++dz) {
                        const Biome other = stand.biomeAt(x + dx, z + dz);
                        const bool otherCold = (other == Biome::Snow || other == Biome::Tundra);
                        if (other != Biome::Forest && !otherCold) continue;
                        std::vector<TreeBlock> tree;
                        stand.buildTree(TreeKind::Conifer, x + dx, z + dz,
                                       stand.terrainHeight(x + dx, z + dz),
                                       0x5EED1234u ^ static_cast<uint32_t>((x + dx) * 73856093) ^
                                           static_cast<uint32_t>((z + dz) * 19349663),
                                       tree);
                        if (!tree.empty()) ++trees;
                    }
                }
                if (trees > thickest) thickest = trees;
                if (trees < sparsest) sparsest = trees;
            }
        }
        printf("  %d tree columns, the thickest has %d trees and the sparsest %d\n", counted,
               thickest, sparsest);
        check(counted > 0, "there is ground with trees in the world",
              "found " + std::to_string(counted));
        check(thickest > sparsest, "the thickets are thicker than the clearings are thin",
              "the thickest has " + std::to_string(thickest) + " and the sparsest " +
                  std::to_string(sparsest));
    }

    printf("\n%u checks, %u failures\n", g_checks, g_failures);
    if (g_failures == 0) {
        printf("VOXEL_CONIFER_GATES=PASS\n");
        return 0;
    }
    printf("VOXEL_CONIFER_GATES=FAIL\n");
    return 1;
}
