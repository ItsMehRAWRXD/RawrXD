#include "streaming/streaming.hpp"
#include <cassert>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>

int main() {
    using namespace kg::stream;
    try {
        std::cout << "Test 1: Config validation\n";
        Config c; c.activeRadius=1; c.cacheLimit=10; c.resolution=17;
        assert(validConfig(c));
        std::cout << "Test 1 PASS\n";
        
        std::cout << "Test 2: keyAt\n";
        assert(keyAt(-0.1,-64,64)==(ChunkKey{-1,-1}));
        assert(keyAt(64,0,64)==(ChunkKey{1,0}));
        std::cout << "Test 2 PASS\n";
        
        std::cout << "Test 3: heightAt determinism\n";
        assert(heightAt(12,31,c.seed)==heightAt(12,31,c.seed));
        std::cout << "Test 3 PASS\n";
        
        std::cout << "Test 4: caveField determinism\n";
        assert(caveField(10,5,2,c.seed)==caveField(10,5,2,c.seed));
        std::cout << "Test 4 PASS\n";
        
        std::cout << "Test 5: caveSolid\n";
        assert(caveSolid(1,2,3,c.seed,1));
        std::cout << "Test 5 PASS\n";
        
        std::cout << "Test 6: buildTerrainChunk\n";
        auto m=buildTerrainChunk({0,0},c,0);
        std::cout << "  vertices: " << m.vertices.size() << " indices: " << m.indices.size() << "\n";
        assert(m.vertices.size()==289 && m.indices.size()==1536);
        std::cout << "Test 6 PASS\n";
        
        std::cout << "Test 7: adjacent chunk matching\n";
        auto adjacent=buildTerrainChunk({1,0},c,0);
        for(int z=0;z<17;++z){
            auto a=m.vertices[size_t(z)*17+16].p;
            auto b=adjacent.vertices[size_t(z)*17].p;
            assert(a.x==b.x && a.y==b.y && a.z==b.z);
        }
        std::cout << "Test 7 PASS\n";
        
        std::cout << "Test 8: buildCaveMask\n";
        auto mask=buildCaveMask({0,0},c,0);
        assert(mask.size()==m.vertices.size());
        std::cout << "Test 8 PASS\n";
        
        std::cout << "Test 9: fingerprint\n";
        Chunk ch; ch.key={0,0}; ch.mesh=m; ch.caveMask=mask;
        assert(fingerprint(ch)==fingerprint(ch));
        std::cout << "Test 9 PASS\n";
        
        std::cout << "Test 10: lodForDistance\n";
        assert(lodForDistance(0,64)==0);
        assert(lodForDistance(128,64)==1);
        std::cout << "Test 10 PASS\n";
        
        std::cout << "Test 11: desiredChunks\n";
        assert(desiredChunks(0,0,c).size()==9);
        std::cout << "Test 11 PASS\n";
        
        std::cout << "Test 12: intersectsViewRadius\n";
        assert(intersectsViewRadius({0,0},32,32,1,64));
        std::cout << "Test 12 PASS\n";
        
        std::cout << "Test 13: buildBridge\n";
        auto bridge=buildBridge({0,0,0},{100,0,0},12,20);
        assert(bridge.vertices.size()==8 && bridge.indices.size()==36);
        std::cout << "Test 13 PASS\n";
        
        std::cout << "Test 14: ChunkStreamer\n";
        ChunkStreamer s(c);
        s.update(0,0);
        assert(s.stats().generated==9 && s.stats().resident==9);
        std::cout << "Test 14a PASS\n";
        
        auto hash=s.find({0,0})->fingerprint;
        s.update(0,0);
        assert(s.stats().cacheHits==9 && s.find({0,0})->fingerprint==hash);
        std::cout << "Test 14b PASS\n";
        
        s.update(192,0);
        assert(s.stats().resident<=10 && s.stats().evictions>0);
        std::cout << "Test 14c PASS\n";
        
        std::cout << "Test 15: exportChunkManifest\n";
        auto p=std::filesystem::temp_directory_path()/"kartgib_drop08_manifest.json";
        exportChunkManifest(s,p);
        {
            std::ifstream in(p);
            std::string data((std::istreambuf_iterator<char>(in)),{});
            assert(data.find("fingerprint")!=std::string::npos);
        }
        std::filesystem::remove(p);
        std::cout << "Test 15 PASS\n";
        
        std::cout << "Test 16: bad config\n";
        Config bad=c; bad.cacheLimit=1;
        assert(!validConfig(bad));
        std::cout << "Test 16 PASS\n";
        
        std::cout << "STREAMING_TESTS_PASS\n";
    } catch (const std::exception& e) {
        std::cerr << "EXCEPTION: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "UNKNOWN EXCEPTION\n";
        return 2;
    }
    return 0;
}
