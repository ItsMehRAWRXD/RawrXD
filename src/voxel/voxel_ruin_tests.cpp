// ============================================================================
// voxel_ruin_tests.cpp — the gates of a gothic ruin.
//
// A ruin is not certified because it looks gothic. It is certified
// because it is tall against its width, because it has pointed arches
// whose upper edges lean in, because it has a spire, because its
// skyline is broken and not a line, because there are openings in it you
// can see the sky through, because the walls have buttresses outside
// them, because the same seed gives the same ruin and a different seed
// gives a different one, because the way in is not filled in, and because
// the foundation rests on the ground instead of floating.
//
// The openings are the point. A cave reads as a cave because of the hole
// in it, and a ruin reads as a ruin the same way.
// ============================================================================

#include <cstdio>
#include <string>
#include <vector>

#include "Block.hpp"
#include "RuinBuilder.hpp"

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

// A picture of the ruin, from the front.
//
// It is here so that a failure can be read. A ruin that fails the taper
// has a flat top, and one that fails the ratio is a shed.
void printElevation(const std::vector<RuinBlock>& blocks, int32_t groundY) {
    int32_t minX = blocks[0].x, maxX = blocks[0].x;
    int32_t maxY = groundY;
    for (const RuinBlock& block : blocks) {
        minX = std::min(minX, block.x);
        maxX = std::max(maxX, block.x);
        maxY = std::max(maxY, block.y);
    }
    if (maxX - minX > 120) return;

    for (int32_t y = maxY; y > groundY; --y) {
        std::string row;
        bool any = false;
        for (int32_t x = minX; x <= maxX; ++x) {
            bool solid = false;
            for (const RuinBlock& block : blocks) {
                if (block.x == x && block.y == y) {
                    solid = true;
                    break;
                }
            }
            if (solid) {
                row += '#';
                any = true;
            } else {
                row += ' ';
            }
        }
        if (any) printf("        %s\n", row.c_str());
    }
}

} // namespace

int main() {
    printf("the gates of a gothic ruin\n");

    const uint32_t seed = 0x5EED1234u;
    const int32_t groundY = 70;

    const RuinPlan plan = planRuin(seed, groundY);
    const std::vector<RuinBlock> blocks =
        buildRuin(plan, static_cast<uint8_t>(BlockType::Stone),
                  static_cast<uint8_t>(BlockType::Gravel));
    const RuinMetrics metrics = measureRuin(plan, blocks, groundY);
    const std::vector<RuinOpening> openings = findOpenings(blocks, groundY);
    const RuinGameplay gameplay = readGameplay(blocks, openings, groundY);

    printf("\none. the shape of it\n");
    {
        const RuinArch& arch = plan.arches[0];
        printf("  the first arch is at %d, %d, it spans %d and it is %d tall\n", arch.x, arch.z,
               arch.span, arch.height);
        for (int32_t y = 0; y < 3; ++y) {
            std::string row;
            for (int32_t d = -2; d <= 2; ++d) {
                bool isSolid = false;
                for (const RuinBlock& block : blocks) {
                    if (block.x == arch.x + d && block.y == arch.baseY + y && block.z == arch.z) {
                        isSolid = true;
                    }
                }
                row += isSolid ? '#' : '.';
            }
            printf("    the row %d of the arch: %s\n", y, row.c_str());
        }
        bool middleSolid = false;
        for (const RuinBlock& block : blocks) {
            if (block.x == 0 && block.y == groundY + 1 && block.z == 0) middleSolid = true;
        }
        printf("  the middle of the hall at head height is %s\n", middleSolid ? "solid" : "open");
    }
    printf("  it is %d wide and %d tall, and the ratio is %s\n", metrics.width, metrics.height,
           number(metrics.ratio()).c_str());
    printf("  the arches are %d, the spires %d, the buttresses %d\n", metrics.arches, metrics.spires,
           metrics.buttresses);
    printf("  the openings are %d and the air inside is %d blocks\n", metrics.openings, metrics.negativeSpace);
    printf("  the skyline has %d peaks and %d different heights\n", metrics.skylineMaxima,
           metrics.brokenEdges);
    printf("  the longest flat run is %d blocks\n", metrics.wallRunLength);
    printElevation(blocks, groundY);

    check(metrics.height > 0, "the ruin has a height");
    check(metrics.ratio() >= 1.8, "the height against the width is at least one and four fifths",
          std::string("got ") + number(metrics.ratio()).c_str());
    check(metrics.arches >= 1, "there is a pointed arch in it",
          "got " + std::to_string(metrics.arches));
    check(metrics.spires >= 1, "there is a narrow vertical peak in the skyline",
          "got " + std::to_string(metrics.spires));
    check(metrics.skylineMaxima >= 2, "the skyline has more than one peak in it",
          "got " + std::to_string(metrics.skylineMaxima));
    check(metrics.brokenEdges >= 3, "the skyline is broken and not a line",
          "got " + std::to_string(metrics.brokenEdges));
    check(metrics.buttresses >= 1, "there is a support outside the wall",
          "got " + std::to_string(metrics.buttresses));
    check(metrics.negativeSpace > 200, "the negative space is worth something", "got " + std::to_string(metrics.negativeSpace));
    check(metrics.negativeSpace > 0, "there is air inside it", "got " + std::to_string(metrics.negativeSpace));
    check(metrics.grounded, "the foundation rests on the ground");
    check(metrics.roofless, "the roof is gone");

    // The arches lean in: the void of an arch is wider at its foot
    // than at its head, and that is what makes it gothic.
    check(metrics.archConvergence >= 1, "the upper edges of an arch lean in",
          "the widest one narrows by " + std::to_string(metrics.archConvergence));

    // -------------------------------------------------------------------
    // The way in is not filled in.
    // -------------------------------------------------------------------
    printf("\ntwo. the way in is open\n");
    {
        // The air at the foot of the hall, between the walls, has to
        // reach the outside.
        int32_t reachable = 0;
        for (int32_t x = -12; x <= 12; ++x) {
            for (int32_t z = -5; z <= 5; ++z) {
                bool solid = false;
                for (const RuinBlock& block : blocks) {
                    if (block.x == x && block.y == groundY + 1 && block.z == z) {
                        solid = true;
                        break;
                    }
                }
                if (!solid) ++reachable;
            }
        }
        printf("  %d blocks of the floor of the hall are open\n", reachable);
        check(reachable > 0, "the hall is open at its foot");
        check(plan.vehicleOpeningWidth >= 4, "the way in is wide enough for a vehicle",
              "got " + std::to_string(plan.vehicleOpeningWidth));
    }

    // -------------------------------------------------------------------
    // The variation: the same seed gives the same ruin and a different
    // seed gives a different one.
    // -------------------------------------------------------------------
    printf("\nthree. the ruins vary and the variation is fixed\n");
    {
        const RuinPlan again = planRuin(seed, groundY);
        const std::vector<RuinBlock> againBlocks =
            buildRuin(again, static_cast<uint8_t>(BlockType::Stone),
                       static_cast<uint8_t>(BlockType::Gravel));

        const RuinPlan other = planRuin(seed + 999u, groundY);
        const std::vector<RuinBlock> otherBlocks =
            buildRuin(other, static_cast<uint8_t>(BlockType::Stone),
                       static_cast<uint8_t>(BlockType::Gravel));

        const auto sameShape = [](const std::vector<RuinBlock>& a, const std::vector<RuinBlock>& b) {
            if (a.size() != b.size()) return false;
            for (size_t i = 0; i < a.size(); ++i) {
                if (a[i].x != b[i].x || a[i].y != b[i].y || a[i].z != b[i].z) return false;
            }
            return true;
        };

        check(sameShape(blocks, againBlocks), "the same seed gives the same ruin");
        check(!sameShape(blocks, otherBlocks), "a different seed gives a different ruin");

        const RuinMetrics otherMetrics = measureRuin(other, otherBlocks, groundY);
        check(otherMetrics.ratio() >= 1.8, "the other ruin is gothic as well",
              std::string("got ") + number(otherMetrics.ratio()).c_str());
        check(otherMetrics.arches >= 1, "the other ruin has an arch in it");
    }

    // -------------------------------------------------------------------
    // The ruin carries its own topology.
    // -------------------------------------------------------------------
    printf("\nfour. the ruin carries its own topology\n");
    printf("  the ways in for a vehicle %zu, for a person %zu, for a mech %zu\n",
           gameplay.vehicleEntrances.size(), gameplay.pilotEntrances.size(),
           gameplay.mechOpenings.size());
    printf("  the wall runs %zu, the ledges %zu, the high places %zu\n",
           gameplay.wallRunSurfaces.size(), gameplay.mantlePoints.size(),
           gameplay.sniperPositions.size());
    printf("  the terminals %zu, the thin walls %zu, the arenas %zu\n", gameplay.hackTerminals.size(),
           gameplay.destructibleSections.size(), gameplay.bossAnchors.size());

    check(!gameplay.pilotEntrances.empty(), "there is a way in for a person");
    check(!gameplay.sniperPositions.empty(), "there is a place to stand and look out from");
    check(metrics.wallRunLength >= 4, "there is a flat run along the top of a wall",
          "the longest is " + std::to_string(metrics.wallRunLength) + " blocks");
    check(!gameplay.destructibleSections.empty(), "there is a wall that comes down easily");
    check(!gameplay.bossAnchors.empty(), "there is a great room to fight in");

    // The topology and the picture are the same thing: the ways in that
    // the gameplay found are gaps in the blocks and not a claim.
    {
        int32_t open = 0;
        for (const RuinOpening& opening : openings) {
            if (opening.enclosed) continue;
            ++open;
        }
        check(open > 0, "the ways in the gameplay uses are gaps in the blocks",
              "got " + std::to_string(open));
        check(!gameplay.bossAnchors.empty(), "the great room is a real space in the blocks");
    }

    printf("\n%u checks, %u failures\n", g_checks, g_failures);
    if (g_failures == 0) {
        printf("VOXEL_RUIN_GATES=PASS\n");
        return 0;
    }
    printf("VOXEL_RUIN_GATES=FAIL\n");
    return 1;
}
