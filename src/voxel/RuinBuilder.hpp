// ============================================================================
// RuinBuilder.hpp — the gothic ruin.
//
// A ruin is a piece of architecture that has been broken. What makes it
// recognisable is not the detail on it; it is the silhouette and the holes
// in it. A gothic ruin is tall and narrow, it has a broken skyline, it has
// pointed arches, and it has openings you can see the sky through.
//
// So the ruin is built from a plan, the plan becomes blocks, and the same
// blocks are what the renderer draws and what the certification measures.
// There is one representation, and the gates measure the thing that is
// drawn.
//
// The openings are not decoration. The same blocks that make the arch
// voids are what a vehicle comes through, what a person climbs into, what
// a wall run goes along and what a sniper stands on, so the ruin carries
// its own topology and the thing that is pretty and the thing that is
// played are the same thing.
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sunshine {

// The pieces a ruin is made of.
enum class RuinPiece : uint8_t {
    Nave,        // the hall
    Tower,       // a tower at the end of the hall
    Spire,       // the point on top of a tower
    Arch,        // a pointed arch
    Buttress,    // a support outside a wall
    BrokenWall,  // a wall that is not all there
};

// One piece of a plan.
struct RuinPart {
    RuinPiece piece = RuinPiece::Nave;
    int32_t x = 0;      // the foot of the piece
    int32_t y = 0;      // the ground it stands on
    int32_t z = 0;
    int32_t width = 0;  // along x
    int32_t depth = 0;  // along z
    int32_t height = 0; // up
    uint32_t seed = 0;  // the piece's own seed
};

// A pointed arch, as the plan says it is.
//
// The plan says where the arches are, and the blocks are cut to match, and
// the certification then checks the blocks: the cells of the arch have to
// be empty, and the arch has to narrow as it goes up. The plan is never
// taken on trust.
struct RuinArch {
    int32_t x = 0;        // the centre of the arch
    int32_t z = 0;        // the plane of the wall it is in
    int32_t baseY = 0;     // the ground it stands on
    int32_t span = 5;      // the width at its foot
    int32_t height = 11;   // how tall it is
    bool alongX = true;    // is the wall running along x
};

// The plan of a ruin: the pieces and where they are.
struct RuinPlan {
    std::vector<RuinPart> parts;
    std::vector<RuinArch> arches;
    int32_t seed = 0;
    int32_t groundY = 0;

    // The opening the ruin has for a vehicle, in the plan.
    int32_t vehicleOpeningWidth = 0;
    int32_t vehicleOpeningHeight = 0;
};

// One block of a ruin.
struct RuinBlock {
    int32_t x = 0;
    int32_t y = 0;
    int32_t z = 0;
    uint8_t block = 0;
};

// An opening in a ruin: the negative space.
struct RuinOpening {
    int32_t x = 0;
    int32_t y = 0;
    int32_t z = 0;
    int32_t width = 0;   // along x
    int32_t height = 0;  // up
    int32_t depth = 0;   // along z
    bool enclosed = false;   // is it a hole in the building
    bool wide = false;      // is it wide enough for a vehicle
};

// What the ruin is for, read off the same blocks.
struct RuinGameplay {
    std::vector<int32_t> vehicleEntrances;  // the openings a vehicle fits through
    std::vector<int32_t> pilotEntrances;    // the openings a person fits through
    std::vector<int32_t> wallRunSurfaces;   // the flat runs along the top of a wall
    std::vector<int32_t> mantlePoints;     // the ledges a person can pull themselves onto
    std::vector<int32_t> sniperPositions;  // the high places
    std::vector<int32_t> hackTerminals;    // the solid faces at the right height
    std::vector<int32_t> destructibleSections;  // the thin walls
    std::vector<int32_t> mechOpenings;     // the openings a mech fits through
    std::vector<int32_t> bossAnchors;      // the centres of the great voids
};

// The measurements of a ruin, read off the blocks that were built.
struct RuinMetrics {
    int32_t groundY = 0;
    int32_t height = 0;       // from the ground to the highest point
    int32_t width = 0;        // the widest it is
    int32_t depth = 0;
    int32_t blocks = 0;

    int32_t arches = 0;       // the pointed arches
    int32_t archConvergence = 0;  // how much the widest one narrows
    int32_t spires = 0;       // the narrow vertical peaks
    int32_t buttresses = 0;   // the supports outside the walls
    int32_t openings = 0;     // the holes in it
    int32_t negativeSpace = 0;// the volume of the air inside it
    int32_t enclosedVoid = 0; // the volume of the holes
    int32_t skylineMaxima = 0;// the unequal peaks of the skyline
    int32_t brokenEdges = 0;  // the steps in the broken skyline
    int32_t wallRunLength = 0;// the longest flat run along a wall

    bool grounded = false;    // does the foundation rest on the ground
    bool roofless = false;   // is the top open to the sky

    double ratio() const {
        return width > 0 ? static_cast<double>(height) / static_cast<double>(width) : 0.0;
    }
};

// The plan of a ruin, from a seed.
//
// The same seed always gives the same plan, and a different seed gives a
// different one.
RuinPlan planRuin(uint32_t seed, int32_t groundY);

// The blocks of a ruin, from a plan.
//
// The plan is the only description of the ruin and the blocks are made
// from it and from nothing else.
std::vector<RuinBlock> buildRuin(const RuinPlan& plan, uint8_t wallBlock, uint8_t floorBlock);

// The measurements of a ruin, read off the blocks that were built.
//
// The plan is handed in so that the arches can be looked for, and the
// plan is never taken on trust: every arch it claims is checked against
// the blocks.
RuinMetrics measureRuin(const RuinPlan& plan, const std::vector<RuinBlock>& blocks,
                         int32_t groundY);

// The top of the ruin: the point that a viewpoint wants to see.
//
// It is the tip of the tallest spire, because that is the part of a
// gothic building that is against the sky.
struct RuinViewpoint {
    int32_t x = 0;
    int32_t y = 0;
    int32_t z = 0;
    int32_t groundY = 0;
};

// The point of a ruin that a camera is pointed at.
RuinViewpoint ruinViewpoint(const RuinPlan& plan);

// The openings of a ruin, and what they are for.
//
// The openings are found from the blocks and the space around them, so
// that the thing that is drawn and the thing that is played cannot drift
// apart.
std::vector<RuinOpening> findOpenings(const std::vector<RuinBlock>& blocks, int32_t groundY);

RuinGameplay readGameplay(const std::vector<RuinBlock>& blocks,
                          const std::vector<RuinOpening>& openings,
                          int32_t groundY);

} // namespace sunshine
