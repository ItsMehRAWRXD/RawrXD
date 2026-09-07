#pragma once
#include "../../cli/style/rawr_file_watcher.hpp"
#include "incremental.hpp"
#include <string>
namespace rawr::product {

struct WatchIndex {
    rawr::style::FileWatcher watch;
    IncrementalIndex inc;
    int dirty = 0;

    bool start(const std::string& root) {
        inc.idx.root = root;
        return watch.start(root);
    }
    int pollAndIngest(const std::string& path) {
        if (watch.poll(0)) dirty = 1;
        if (!dirty) return 0;
        dirty = 0;
        return inc.ingest(path) ? 1 : 0;
    }
    void stop() { watch.stop(); }
};

} // namespace rawr::product
