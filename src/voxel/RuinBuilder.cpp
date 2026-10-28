// ============================================================================
// RuinBuilder.cpp — the gothic ruin.
//
// A cathedral that has been broken: a hall with a row of pointed arches
// down each side, a tower at each end, a spire on the towers, buttresses
// along the walls, a roof that is not there any more, and a wall that has
// fallen in.
//
// The arches are the point of it. A gothic arch is a hole with two edges
// that lean in towards each other, and a building made of those reads as
// gothic from any distance, because the sky comes through the holes in a
// shape that says so.
//
// The measurements are read back out of the blocks, not off the plan, so
// that what is certified is what is drawn.
// ============================================================================

#include "RuinBuilder.hpp"

#include <algorithm>
#include <cmath>
#include <map>
#include <set>

#include "Block.hpp"
#include "Math.hpp"

namespace sunshine {

namespace {

// The half width of a pointed arch at a given height.
//
// The opening starts as wide as the arch and closes to a point, and the
// edges lean in, which is what makes it gothic rather than round.
int32_t archHalfWidth(int32_t span, int32_t height, int32_t y) {
    if (y < 0 || y >= height || height <= 0) return 0;
    const double t = 1.0 - static_cast<double>(y) / static_cast<double>(height);
    return static_cast<int32_t>(static_cast<double>(span / 2) * std::pow(t, 0.65) + 0.5);
}

// The hash of a number, for the variation.
uint32_t mix(uint32_t value) {
    value ^= value >> 16;
    value *= 0x7feb352dU;
    value ^= value >> 15;
    value *= 0x846ca68bU;
    value ^= value >> 16;
    return value;
}

struct Key {
    int32_t x, y, z;
    bool operator<(const Key& other) const {
        if (x != other.x) return x < other.x;
        if (y != other.y) return y < other.y;
        return z < other.z;
    }
};

} // namespace

// The plan of a ruin.
RuinPlan planRuin(uint32_t seed, int32_t groundY) {
    RuinPlan plan;
    plan.seed = static_cast<int32_t>(seed);
    plan.groundY = groundY;

    // The hall. It is long and narrow, because that is what gothic is:
    // the height is meant to be read against the width.
    RuinPart nave;
    nave.piece = RuinPiece::Nave;
    nave.x = -7;
    nave.z = -5;
    nave.width = 14;
    nave.depth = 10;
    nave.height = 30 + static_cast<int32_t>(mix(seed ^ 0x11U) % 8U);
    nave.seed = mix(seed);
    plan.parts.push_back(nave);

    // The arches down each side of the hall.
    for (int32_t side = 0; side < 2; ++side) {
        const int32_t z = side == 0 ? nave.z : nave.z + nave.depth - 1;
        for (int32_t arch = -1; arch <= 1; ++arch) {
            RuinArch opening;
            opening.x = nave.x + nave.width / 2 + arch * 4;
            opening.z = z;
            opening.baseY = groundY + 1;
            opening.span = 5;
            opening.height = 13;
            opening.alongX = true;
            plan.arches.push_back(opening);
        }
    }

    // The towers at the ends, and the spires on them.
    for (int side = 0; side < 2; ++side) {
        const int32_t sign = side == 0 ? -1 : 1;

        RuinPart tower;
        tower.piece = RuinPiece::Tower;
        tower.x = sign < 0 ? nave.x - 5 : nave.x + nave.width;
        tower.z = -3;
        tower.width = 5;
        tower.depth = 6;
        tower.height = nave.height + 8 + static_cast<int32_t>(mix(seed ^ (0x22U + side)) % 6U);
        tower.seed = mix(seed ^ (0x30U + side));
        plan.parts.push_back(tower);

        RuinPart spire;
        spire.piece = RuinPiece::Spire;
        spire.x = tower.x + 1;
        spire.z = tower.z + 1;
        spire.width = 3;
        spire.depth = 4;
        spire.height = 14 + static_cast<int32_t>(mix(seed ^ (0x40U + side)) % 8U);
        spire.seed = mix(seed ^ (0x50U + side));
        plan.parts.push_back(spire);
    }

    // The buttresses: the supports that stand outside the walls.
    for (int32_t i = 0; i < 4; ++i) {
        const int32_t x = nave.x + 2 + i * 3;
        for (int32_t side = 0; side < 2; ++side) {
            RuinPart buttress;
            buttress.piece = RuinPiece::Buttress;
            buttress.x = x;
            buttress.z = side == 0 ? nave.z - 2 : nave.z + nave.depth;
            buttress.width = 2;
            buttress.depth = 2;
            buttress.height = 13 + static_cast<int32_t>(mix(seed ^ (0x60U + i * 2 + side)) % 7U);
            buttress.seed = mix(seed ^ (0x70U + i * 2 + side));
            plan.parts.push_back(buttress);
        }
    }

    // The broken wall: the side of the hall, with a piece of it gone.
    RuinPart wall;
    wall.piece = RuinPiece::BrokenWall;
    wall.x = nave.x;
    wall.z = nave.z + nave.depth - 1;
    wall.width = nave.width;
    wall.depth = 1;
    wall.height = 10 + static_cast<int32_t>(mix(seed ^ 0x80U) % 6U);
    wall.seed = mix(seed ^ 0x90U);
    plan.parts.push_back(wall);

    // The way in: the opening at the foot of the hall that a vehicle
    // comes through, and that the ruin is measured by.
    plan.vehicleOpeningWidth = 5;
    plan.vehicleOpeningHeight = 7;

    // Every piece stands on the ground the plan was made for.
    for (RuinPart& part : plan.parts) {
        part.y = groundY;
    }

    return plan;
}

// The blocks of a ruin.
std::vector<RuinBlock> buildRuin(const RuinPlan& plan, uint8_t wallBlock, uint8_t floorBlock) {
    std::vector<RuinBlock> blocks;

    const auto put = [&](int32_t x, int32_t y, int32_t z, uint8_t block) {
        RuinBlock b;
        b.x = x;
        b.y = y;
        b.z = z;
        b.block = block;
        blocks.push_back(b);
    };

    // The arches are cut out of the walls, and the plan says where they
    // are so that the certification can check them against the blocks.
    // The height that is given is the height above the foot of the
    // piece, which is how the builder counts.
    const auto inArchHole = [&](int32_t x, int32_t y, int32_t z) {
        // The row of the wall, counted from its foot. The arch stands on
        // the floor, so its first row is the one above it.
        const int32_t row = y - 1;
        for (const RuinArch& arch : plan.arches) {
            if (arch.alongX) {
                if (z != arch.z) continue;
                const int32_t local = x - arch.x;
                if (std::abs(local) > arch.span / 2) continue;
                if (row < 0 || row >= arch.height) continue;
                if (std::abs(local) < archHalfWidth(arch.span, arch.height, row)) {
                    return true;
                }
            } else {
                if (x != arch.x) continue;
                const int32_t local = z - arch.z;
                if (std::abs(local) > arch.span / 2) continue;
                if (row < 0 || row >= arch.height) continue;
                if (std::abs(local) < archHalfWidth(arch.span, arch.height, row)) {
                    return true;
                }
            }
        }
        return false;
    };

    for (const RuinPart& part : plan.parts) {
        switch (part.piece) {
            case RuinPiece::Nave: {
                // The floor of the hall.
                for (int32_t x = 0; x < part.width; ++x) {
                    for (int32_t z = 0; z < part.depth; ++z) {
                        put(part.x + x, part.y, part.z + z, floorBlock);
                    }
                }

                // The walls.
                for (int32_t x = 0; x < part.width; ++x) {
                    for (int32_t z = 0; z < part.depth; ++z) {
                        const bool onSide = (z == 0 || z == part.depth - 1);
                        const bool onEnd = (x == 0 || x == part.width - 1);
                        if (!onSide && !onEnd) continue;

                        for (int32_t y = 0; y < part.height; ++y) {
                            bool hole = false;

                            if (onSide && !onEnd) {
                                // The arches down each side: a hole with
                                // edges that lean in. The height that is
                                // given is the height above the foot of
                                // the wall.
                                hole = inArchHole(part.x + x, y, part.z + z);
                            } else if (onEnd && !onSide) {
                                // The way in, at the foot of the hall.
                                const int32_t local = z - part.depth / 2;
                                const int32_t half =
                                    archHalfWidth(plan.vehicleOpeningWidth + 2, plan.vehicleOpeningHeight, y);
                                if (std::abs(local) < half && y < plan.vehicleOpeningHeight) hole = true;
                            }

                            if (hole) continue;
                            put(part.x + x, part.y + y, part.z + z, wallBlock);
                        }
                    }
                }
                break;
            }

            case RuinPiece::Tower: {
                // The tower is hollow, and it has a window near the top
                // that the light comes through.
                for (int32_t x = 0; x < part.width; ++x) {
                    for (int32_t z = 0; z < part.depth; ++z) {
                        const bool onEdge =
                            (x == 0 || x == part.width - 1 || z == 0 || z == part.depth - 1);
                        if (!onEdge) continue;

                        for (int32_t y = 0; y < part.height; ++y) {
                            // The belfry: four windows, one in each
                            // face, near the top.
                            bool hole = false;
                            if (y > part.height - 10 && y < part.height - 4) {
                                const int32_t centreX = part.width / 2;
                                const int32_t centreZ = part.depth / 2;
                                if (x == 0 || x == part.width - 1) {
                                    if (std::abs(z - centreZ) < 1) hole = true;
                                } else {
                                    if (std::abs(x - centreX) < 1) hole = true;
                                }
                            }
                            if (hole) continue;
                            put(part.x + x, part.y + y, part.z + z, wallBlock);
                        }
                    }
                }
                break;
            }

            case RuinPiece::Spire: {
                // The spire is a pyramid, and it is the point of the
                // skyline.
                for (int32_t y = 0; y < part.height; ++y) {
                    const int32_t halfW = part.width / 2 - (y * part.width) / (2 * part.height);
                    const int32_t halfD = part.depth / 2 - (y * part.depth) / (2 * part.height);
                    for (int32_t x = -halfW; x <= halfW; ++x) {
                        for (int32_t z = -halfD; z <= halfD; ++z) {
                            put(part.x + x, part.y + y, part.z + z, wallBlock);
                        }
                    }
                }
                break;
            }

            case RuinPiece::Buttress: {
                // The buttress is a solid pier that leans against the
                // wall from the outside.
                for (int32_t x = 0; x < part.width; ++x) {
                    for (int32_t z = 0; z < part.depth; ++z) {
                        for (int32_t y = 0; y < part.height; ++y) {
                            put(part.x + x, part.y + y, part.z + z, wallBlock);
                        }
                    }
                }
                break;
            }

            case RuinPiece::BrokenWall: {
                // The broken wall: its top steps down and up, so the
                // skyline is not a line.
                for (int32_t x = 0; x < part.width; ++x) {
                    const uint32_t r = mix(part.seed ^ static_cast<uint32_t>(x));
                    int32_t height = part.height - static_cast<int32_t>(r % 7U);
                    if (height < 3) height = 3;
                    for (int32_t z = 0; z < part.depth; ++z) {
                        for (int32_t y = 0; y < height; ++y) {
                            put(part.x + x, part.y + y, part.z + z, wallBlock);
                        }
                    }
                }
                break;
            }
        }
    }

    return blocks;
}

// The point of a ruin that a camera is pointed at.
//
// It is the tip of the tallest spire, because that is the part of a
// gothic building that is against the sky, and a picture of a building
// without its spire against the sky is a picture of a hill.
RuinViewpoint ruinViewpoint(const RuinPlan& plan) {
    RuinViewpoint viewpoint;
    viewpoint.groundY = plan.groundY;

    int32_t highest = 0;
    int32_t tipX = 0;
    int32_t tipZ = 0;

    for (const RuinPart& part : plan.parts) {
        if (part.piece != RuinPiece::Spire) continue;
        const int32_t top = part.y + part.height;
        if (top <= highest) continue;
        highest = top;
        tipX = part.x + part.width / 2;
        tipZ = part.z + part.depth / 2;
    }

    viewpoint.x = tipX;
    viewpoint.y = highest;
    viewpoint.z = tipZ;
    return viewpoint;
}

// The measurements of a ruin, read back out of the blocks.
// The measurements of a ruin, read back out of the blocks.
//
// The plan is handed in so that the arches can be looked for, and the
// plan is never taken on trust: every arch it claims is checked against
// the blocks that were built, and the arch has to be empty and it has to
// narrow as it goes up.
RuinMetrics measureRuin(const RuinPlan& plan, const std::vector<RuinBlock>& blocks,
                         int32_t groundY) {
    RuinMetrics metrics;
    metrics.groundY = groundY;
    if (blocks.empty()) return metrics;

    std::set<Key> solid;
    int32_t minX = blocks[0].x, maxX = blocks[0].x;
    int32_t minY = blocks[0].y, maxY = blocks[0].y;
    int32_t minZ = blocks[0].z, maxZ = blocks[0].z;

    for (const RuinBlock& block : blocks) {
        solid.insert(Key{block.x, block.y, block.z});
        minX = std::min(minX, block.x);
        maxX = std::max(maxX, block.x);
        minY = std::min(minY, block.y);
        maxY = std::max(maxY, block.y);
        minZ = std::min(minZ, block.z);
        maxZ = std::max(maxZ, block.z);
    }

    metrics.blocks = static_cast<int32_t>(blocks.size());
    metrics.height = maxY - groundY;
    metrics.width = maxX - minX + 1;
    metrics.depth = maxZ - minZ + 1;
    metrics.grounded = (minY <= groundY + 1);
    metrics.roofless = (maxY - groundY) > 10;

    // The negative space: the air inside the footprint of the ruin.
    // A ruin has no roof, so the air inside it is open to the sky, and
    // the holes in the walls are what a person and a vehicle come
    // through.
    for (int32_t x = minX; x <= maxX; ++x) {
        for (int32_t z = minZ; z <= maxZ; ++z) {
            for (int32_t y = groundY + 1; y <= maxY; ++y) {
                if (solid.count(Key{x, y, z})) continue;
                ++metrics.negativeSpace;
            }
        }
    }

    // The openings.
    {
        const std::vector<RuinOpening> openings = findOpenings(blocks, groundY);
        metrics.openings = static_cast<int32_t>(openings.size());
    }

    // The arches.
    //
    // Each arch of the plan is looked for in the blocks: the cells it
    // claims have to be empty, and the width of the hole has to fall as
    // it goes up, with at least two steps in it, and that is what makes
    // it gothic rather than round.
    for (const RuinArch& arch : plan.arches) {
        int32_t bottomWidth = 0;
        int32_t topWidth = 0;
        int32_t steps = 0;
        int32_t previous = 0;
        bool clean = true;

        for (int32_t y = 0; y < arch.height; ++y) {
            // The hole of the arch at this height, and the cells that
            // have to be empty for it to be a hole.
            const int32_t half = archHalfWidth(arch.span, arch.height, y);
            int32_t width = 0;
            for (int32_t d = -arch.span / 2; d <= arch.span / 2; ++d) {
                const int32_t x = arch.alongX ? arch.x + d : arch.x;
                const int32_t z = arch.alongX ? arch.z : arch.z + d;
                const bool inHole = (std::abs(d) < half);
                const bool isSolid = solid.count(Key{x, arch.baseY + y, z}) > 0;
                if (inHole && isSolid) clean = false;
                if (inHole) ++width;
            }
            if (y == 0) bottomWidth = width;
            if (y == arch.height - 1) topWidth = width;
            if (width != previous) {
                ++steps;
                previous = width;
            }
        }

        if (!clean) continue;
        if (bottomWidth <= topWidth) continue;
        // Two edges that lean in, and the step between them.
        if (steps < 2) continue;
        ++metrics.arches;
        if (bottomWidth - topWidth > metrics.archConvergence) {
            metrics.archConvergence = bottomWidth - topWidth;
        }
    }

    // The skyline: the top of every column, and the peaks in it.
    std::map<std::pair<int32_t, int32_t>, int32_t> skyline;
    for (const RuinBlock& block : blocks) {
        const auto column = std::make_pair(block.x, block.z);
        const auto it = skyline.find(column);
        if (it == skyline.end() || block.y > it->second) skyline[column] = block.y;
    }

    std::set<int32_t> peakHeights;
    for (const auto& column : skyline) {
        const int32_t here = column.second;
        // The height of the ground around it, and a spire stands above
        // the middle of it even though it is surrounded by its own body.
        std::vector<int32_t> around;
        for (int32_t dx = -3; dx <= 3; ++dx) {
            for (int32_t dz = -3; dz <= 3; ++dz) {
                if (dx == 0 && dz == 0) continue;
                const auto it = skyline.find({column.first.first + dx, column.first.second + dz});
                if (it != skyline.end()) around.push_back(it->second);
            }
        }
        if (around.empty()) continue;
        std::sort(around.begin(), around.end());
        const int32_t middle = around[around.size() / 2];
        if (here - middle >= 4) peakHeights.insert(here);
    }
    metrics.skylineMaxima = static_cast<int32_t>(peakHeights.size());
    metrics.spires = metrics.skylineMaxima;

    // The steps in the skyline: the number of different heights the
    // broken edges make.
    std::set<int32_t> edgeHeights;
    for (const auto& column : skyline) edgeHeights.insert(column.second);
    metrics.brokenEdges = static_cast<int32_t>(edgeHeights.size());

    // The longest flat run along the top of a wall: the place a wall
    // run goes. The run is along one wall and not across the building,
    // so the walls are counted one at a time.
    std::map<std::pair<int32_t, int32_t>, std::vector<int32_t>> runsByHeight;
    for (const auto& column : skyline) {
        runsByHeight[{column.second, column.first.second}].push_back(column.first.first);
    }
    for (const auto& run : runsByHeight) {
        std::vector<int32_t> xs = run.second;
        std::sort(xs.begin(), xs.end());
        int32_t length = 0;
        int32_t best = 0;
        for (size_t i = 0; i < xs.size(); ++i) {
            if (i > 0 && xs[i] == xs[i - 1] + 1) {
                ++length;
            } else {
                length = 1;
            }
            best = std::max(best, length);
        }
        metrics.wallRunLength = std::max(metrics.wallRunLength, best);
    }

    // The buttresses: the columns that stand outside the wall of the
    // hall, beside it and not part of it.
    {
        std::set<std::pair<int32_t, int32_t>> supports;
        int32_t hallMinX = 0, hallMaxX = 0, hallMinZ = 0, hallMaxZ = 0;
        bool haveHall = false;
        for (const RuinPart& part : plan.parts) {
            if (part.piece != RuinPiece::Nave) continue;
            hallMinX = part.x;
            hallMaxX = part.x + part.width - 1;
            hallMinZ = part.z;
            hallMaxZ = part.z + part.depth - 1;
            haveHall = true;
        }
        if (haveHall) {
            for (const RuinBlock& block : blocks) {
                const bool beside = (block.z < hallMinZ || block.z > hallMaxZ) &&
                                   block.x >= hallMinX && block.x <= hallMaxX;
                if (beside) supports.insert({block.x, block.z});
            }
            metrics.buttresses = static_cast<int32_t>(supports.size());
        }
    }

    return metrics;
}
// are the way in and the windows.
std::vector<RuinOpening> findOpenings(const std::vector<RuinBlock>& blocks, int32_t groundY) {
    std::vector<RuinOpening> openings;
    if (blocks.empty()) return openings;

    std::set<Key> solid;
    int32_t minX = blocks[0].x, maxX = blocks[0].x;
    int32_t minY = blocks[0].y, maxY = blocks[0].y;
    int32_t minZ = blocks[0].z, maxZ = blocks[0].z;
    for (const RuinBlock& block : blocks) {
        solid.insert(Key{block.x, block.y, block.z});
        minX = std::min(minX, block.x);
        maxX = std::max(maxX, block.x);
        minY = std::min(minY, block.y);
        maxY = std::max(maxY, block.y);
        minZ = std::min(minZ, block.z);
        maxZ = std::max(maxZ, block.z);
    }

    // The air inside the footprint of the ruin, and whether the outside
    // can reach it.
    const int32_t pad = 2;
    const int32_t loX = minX - pad, hiX = maxX + pad;
    const int32_t loZ = minZ - pad, hiZ = maxZ + pad;

    std::set<Key> outside;
    std::vector<Key> stack;

    const auto push = [&](int32_t x, int32_t y, int32_t z) {
        const Key key{x, y, z};
        if (solid.count(key)) return;
        if (outside.count(key)) return;
        outside.insert(key);
        stack.push_back(key);
    };

    // The flood starts from the ground all around the ruin.
    for (int32_t x = loX; x <= hiX; ++x) {
        push(x, groundY, loZ);
        push(x, groundY, hiZ);
    }
    for (int32_t z = loZ; z <= hiZ; ++z) {
        push(loX, groundY, z);
        push(hiX, groundY, z);
    }

    while (!stack.empty()) {
        const Key key = stack.back();
        stack.pop_back();
        const int32_t neighbours[6][3] = {
            {1, 0, 0}, {-1, 0, 0}, {0, 1, 0}, {0, -1, 0}, {0, 0, 1}, {0, 0, -1}};
        for (const auto& n : neighbours) {
            const int32_t nx = key.x + n[0];
            const int32_t ny = key.y + n[1];
            const int32_t nz = key.z + n[2];
            if (ny < groundY || ny > maxY + 1) continue;
            if (nx < loX || nx > hiX || nz < loZ || nz > hiZ) continue;
            push(nx, ny, nz);
        }
    }

    // The air inside the footprint that the flood did not reach is the
    // void of the building, and the pieces of it are the openings.
    std::set<Key> inside;
    for (int32_t x = minX; x <= maxX; ++x) {
        for (int32_t z = minZ; z <= maxZ; ++z) {
            for (int32_t y = groundY + 1; y <= maxY; ++y) {
                const Key key{x, y, z};
                if (solid.count(key)) continue;
                if (outside.count(key)) continue;
                inside.insert(key);
            }
        }
    }

    // The pieces of it, each one an opening.
    std::set<Key> seen;
    for (const Key& start : inside) {
        if (seen.count(start)) continue;

        std::vector<Key> piece;
        std::vector<Key> pending{start};
        seen.insert(start);

        int32_t pMinX = start.x, pMaxX = start.x;
        int32_t pMinY = start.y, pMaxY = start.y;
        int32_t pMinZ = start.z, pMaxZ = start.z;

        while (!pending.empty()) {
            const Key key = pending.back();
            pending.pop_back();
            piece.push_back(key);
            pMinX = std::min(pMinX, key.x);
            pMaxX = std::max(pMaxX, key.x);
            pMinY = std::min(pMinY, key.y);
            pMaxY = std::max(pMaxY, key.y);
            pMinZ = std::min(pMinZ, key.z);
            pMaxZ = std::max(pMaxZ, key.z);

            const int32_t neighbours[6][3] = {
                {1, 0, 0}, {-1, 0, 0}, {0, 1, 0}, {0, -1, 0}, {0, 0, 1}, {0, 0, -1}};
            for (const auto& n : neighbours) {
                const Key next{key.x + n[0], key.y + n[1], key.z + n[2]};
                if (!inside.count(next) || seen.count(next)) continue;
                seen.insert(next);
                pending.push_back(next);
            }
        }

        RuinOpening opening;
        opening.x = pMinX;
        opening.y = pMinY;
        opening.z = pMinZ;
        opening.width = pMaxX - pMinX + 1;
        opening.height = pMaxY - pMinY + 1;
        opening.depth = pMaxZ - pMinZ + 1;
        opening.enclosed = true;

        // The shape of the opening is the shape of the piece of air: an
        // arch is wider at its foot than at its head.
        int32_t bottomWidth = 0;
        int32_t topWidth = 0;
        for (int32_t y = pMinY; y <= pMaxY; ++y) {
            int32_t width = 0;
            for (int32_t x = pMinX; x <= pMaxX; ++x) {
                for (int32_t z = pMinZ; z <= pMaxZ; ++z) {
                    if (inside.count(Key{x, y, z})) ++width;
                }
            }
            if (y == pMinY) bottomWidth = width;
            if (y == pMaxY) topWidth = width;
        }
        opening.wide = (bottomWidth > topWidth) && (opening.width >= 3);

        openings.push_back(opening);
    }

    // The way in: the air at the foot of the hall that the flood can
    // reach, which is the opening a vehicle comes through.
    int32_t wayIns = 0;
    for (int32_t x = minX; x <= maxX; ++x) {
        for (int32_t z = minZ; z <= maxZ; ++z) {
            const Key key{x, groundY + 1, z};
            if (solid.count(key)) continue;
            if (!outside.count(key)) continue;
            // Only the ones that are between the walls of the hall.
            if (x < minX + 2 || x > maxX - 2) continue;
            if (z < minZ + 2 || z > maxZ - 2) continue;
            RuinOpening opening;
            opening.x = x;
            opening.y = groundY + 1;
            opening.z = z;
            opening.width = 1;
            opening.height = 1;
            opening.depth = 1;
            opening.enclosed = false;
            opening.wide = false;
            openings.push_back(opening);
            ++wayIns;
        }
    }

    return openings;
}

// What the ruin is for.
RuinGameplay readGameplay(const std::vector<RuinBlock>& blocks,
                          const std::vector<RuinOpening>& openings,
                          int32_t groundY) {
    RuinGameplay gameplay;
    if (blocks.empty()) return gameplay;

    std::set<Key> solid;
    std::map<std::pair<int32_t, int32_t>, int32_t> skyline;
    for (const RuinBlock& block : blocks) {
        solid.insert(Key{block.x, block.y, block.z});
        const auto column = std::make_pair(block.x, block.z);
        const auto it = skyline.find(column);
        if (it == skyline.end() || block.y > it->second) skyline[column] = block.y;
    }

    // The openings, by what fits through them.
    //
    // The way in is a run of open cells along a wall, and the width of
    // the run is the width of the doorway, which is what decides what
    // goes through it.
    {
        std::map<std::pair<int32_t, int32_t>, std::vector<int32_t>> waysIn;
        for (const RuinOpening& opening : openings) {
            if (opening.enclosed) continue;
            waysIn[{opening.y, opening.z}].push_back(opening.x);
        }

        for (const auto& way : waysIn) {
            std::vector<int32_t> xs = way.second;
            std::sort(xs.begin(), xs.end());
            int32_t length = 0;
            int32_t previous = 0;
            for (size_t i = 0; i < xs.size(); ++i) {
                if (i > 0 && xs[i] == previous + 1) {
                    ++length;
                } else {
                    length = 1;
                }
                previous = xs[i];
                if (length >= 1) gameplay.pilotEntrances.push_back(way.first.first);
                if (length >= 3) gameplay.vehicleEntrances.push_back(way.first.first);
                if (length >= 7) gameplay.mechOpenings.push_back(way.first.first);
            }
        }
    }

    for (const RuinOpening& opening : openings) {
        if (!opening.enclosed) continue;
        // A void a person fits into, a vehicle fits into, a mech fits
        // into.
        if (opening.height >= 2) gameplay.pilotEntrances.push_back(opening.y);
        if (opening.width >= 3 && opening.height >= 4) {
            gameplay.vehicleEntrances.push_back(opening.y);
        }
        if (opening.width >= 7 && opening.height >= 5) {
            gameplay.mechOpenings.push_back(opening.y);
        }
        if (opening.width >= 8 && opening.height >= 8) {
            gameplay.bossAnchors.push_back(opening.y);
        }
    }

    // The great room: the widest open space in the building.
    //
    // A ruin has no roof, so its great room is not shut inside it. It is
    // the wide open space under where the roof was, and that is the room
    // that a fight happens in.
    {
        int32_t minX = 0, maxX = 0, minZ = 0, maxZ = 0;
        bool have = false;
        for (const RuinBlock& block : blocks) {
            if (!have) {
                minX = maxX = block.x;
                minZ = maxZ = block.z;
                have = true;
            }
            minX = std::min(minX, block.x);
            maxX = std::max(maxX, block.x);
            minZ = std::min(minZ, block.z);
            maxZ = std::max(maxZ, block.z);
        }
        if (have) {
            for (int32_t y = groundY + 1; y < groundY + 30; ++y) {
                for (int32_t z = minZ; z <= maxZ; ++z) {
                    int32_t run = 0;
                    for (int32_t x = minX; x <= maxX; ++x) {
                        if (solid.count(Key{x, y, z})) {
                            run = 0;
                            continue;
                        }
                        ++run;
                        if (run >= 8) gameplay.bossAnchors.push_back(y);
                        if (run >= 5) gameplay.vehicleEntrances.push_back(y);
                    }
                }
            }
        }
    }

    // The high places: the top of a column that stands well above the
    // ground.
    for (const auto& column : skyline) {
        const int32_t height = column.second - groundY;
        if (height >= 20) gameplay.sniperPositions.push_back(column.second);
    }

    // The flat runs along the top of a wall.
    std::map<int32_t, std::vector<int32_t>> runsByHeight;
    for (const auto& column : skyline) {
        runsByHeight[column.second].push_back(column.first.first);
    }
    for (const auto& run : runsByHeight) {
        std::vector<int32_t> xs = run.second;
        std::sort(xs.begin(), xs.end());
        int32_t length = 0;
        for (size_t i = 0; i < xs.size(); ++i) {
            if (i > 0 && xs[i] == xs[i - 1] + 1) {
                ++length;
            } else {
                length = 1;
            }
            if (length >= 4) gameplay.wallRunSurfaces.push_back(run.first);
        }
    }

    // The ledges: a block whose top is open and which has a lower step
    // beside it.
    for (const RuinBlock& block : blocks) {
        const bool openAbove = !solid.count(Key{block.x, block.y + 1, block.z});
        const bool stepDown =
            solid.count(Key{block.x, block.y - 1, block.z}) && !solid.count(Key{block.x, block.y, block.z + 1});
        if (openAbove && stepDown) gameplay.mantlePoints.push_back(block.y);
    }

    // The terminals: the solid faces that are at the height a person
    // works at.
    for (const RuinBlock& block : blocks) {
        const int32_t height = block.y - groundY;
        if (height < 1 || height > 4) continue;
        if (!solid.count(Key{block.x, block.y, block.z + 1})) {
            gameplay.hackTerminals.push_back(block.y);
        }
    }

    // The thin walls: the sections that come down easily.
    for (int32_t x = -13; x < 13; ++x) {
        for (int32_t z = -6; z < 6; ++z) {
            for (int32_t y = groundY + 1; y < groundY + 12; ++y) {
                if (!solid.count(Key{x, y, z})) continue;
                // A wall one block thick with air on both sides.
                if (!solid.count(Key{x, y, z - 1}) && !solid.count(Key{x, y, z + 1})) {
                    gameplay.destructibleSections.push_back(y);
                    break;
                }
            }
        }
    }

    return gameplay;
}

} // namespace sunshine
