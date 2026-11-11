#pragma once
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>
#include "worldforge.hpp"
namespace kg::stream {
struct ChunkKey { int x=0,z=0; bool operator<(const ChunkKey& b) const { return x==b.x ? z<b.z : x<b.x; } bool operator==(const ChunkKey&) const = default; };
struct Chunk { ChunkKey key; int resolution=0; double size=0; Mesh mesh; std::vector<uint8_t> caveMask; uint64_t fingerprint=0; };
struct Config { uint64_t seed=42; double chunkSize=64; int resolution=17; int activeRadius=2; int cacheLimit=128; double caveThreshold=0.72; };
struct Bridge { Vec3 start,end; double width=10,deckHeight=0; Mesh mesh; };
struct Stats { uint64_t generated=0,cacheHits=0,evictions=0; size_t resident=0,visible=0; };
uint64_t mix64(uint64_t x);                                     // 01
ChunkKey keyAt(double x,double z,double chunkSize);           // 02
double heightAt(double x,double z,uint64_t seed);              // 03
double caveField(double x,double y,double z,uint64_t seed);    // 04
bool caveSolid(double x,double y,double z,uint64_t seed,double threshold); // 05
Mesh buildTerrainChunk(ChunkKey key,const Config& cfg,int lod); // 06
std::vector<uint8_t> buildCaveMask(ChunkKey key,const Config& cfg,int lod); // 07
uint64_t fingerprint(const Chunk& chunk);                     // 08
int lodForDistance(double distance,double chunkSize,int maxLod=3); // 09
std::vector<ChunkKey> desiredChunks(double x,double z,const Config& cfg); // 10
bool intersectsViewRadius(ChunkKey key,double x,double z,double radius,double chunkSize); // 11
Mesh buildBridge(const Vec3& a,const Vec3& b,double width,double deckHeight); // 12
bool validConfig(const Config& cfg,std::string* why=nullptr); // 13
class ChunkStreamer { // 14: bounded deterministic chunk cache with active-set management
public:
 explicit ChunkStreamer(Config config);
 void update(double cameraX,double cameraZ);
 const Chunk* find(ChunkKey key) const;
 const std::map<ChunkKey,Chunk>& chunks() const {return chunks_;}
 const std::set<ChunkKey>& active() const {return active_;}
 Stats stats() const;
private:
 Config cfg_; std::map<ChunkKey,Chunk> chunks_; std::set<ChunkKey> active_;
 std::map<ChunkKey,uint64_t> lastUsed_; uint64_t tick_=0,generated_=0,hits_=0,evictions_=0;
};
void exportChunkManifest(const ChunkStreamer& streamer,const std::filesystem::path& path); // 15
}
