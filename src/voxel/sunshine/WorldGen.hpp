#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace RawrXD {
namespace Voxel {
namespace sunshine {
constexpr int ChunkSize = 16;
enum class Block : std::uint8_t { Air, Stone, Dirt, Grass, Sand, Water, Wood, Leaves, Brick, Snow };
struct Config {
    std::uint64_t seed=1337;
    std::string world="islands";
    int scale=1, sea=64, mountains=35, erosion=55, caves=40,
        trees=85, temperature=85, humidity=80, rivers=40, structures=35;
    bool valid() const noexcept;
    bool operator==(const Config&) const = default;
};
struct Chunk {
    int cx=0, cy=0, cz=0;
    std::array<Block, ChunkSize*ChunkSize*ChunkSize> blocks{};
    Block at(int x,int y,int z) const noexcept;
    void set(int x,int y,int z,Block b) noexcept;
};
class Generator {
public:
    explicit Generator(Config config = {});
    const Config& config() const noexcept { return cfg_; }
    int height(int x,int z) const noexcept;
    Block sample(int x,int y,int z) const noexcept;
    Chunk generate(int cx,int cy,int cz) const noexcept;
private:
    Config cfg_;
    std::uint64_t hash(int x,int y,int z,std::uint64_t salt) const noexcept;
    double noise(double x,double z,std::uint64_t salt) const noexcept;
    double fractal(double x,double z,std::uint64_t salt,int octaves) const noexcept;
    double islandMask(int x,int z) const noexcept;
    double riverValue(int x,int z) const noexcept;
    Block terrain(int x,int y,int z) const noexcept;
    Block decoration(int x,int y,int z) const noexcept;
};
// Versioned, little-endian, CRC32-protected binary files.
std::vector<std::uint8_t> serializeConfig(const Config& cfg);
Config deserializeConfig(const std::vector<std::uint8_t>& data);
std::vector<std::uint8_t> serializeChunk(const Chunk& chunk);
Chunk deserializeChunk(const std::vector<std::uint8_t>& data);
}
} // namespace Voxel
} // namespace RawrXD
