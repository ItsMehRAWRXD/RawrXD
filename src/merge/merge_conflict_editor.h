// ============================================================================
// merge_conflict_editor.h — Visual 3-Way Merge Conflict Editor
// ============================================================================

#pragma once

#include <string>
#include <vector>

namespace RawrXD {
namespace Merge {

struct ConflictHunk {
    int startLine;
    int endLine;
    std::string ancestor;
    std::string current;
    std::string incoming;
    int resolution;  // 0=unresolved, 1=current, 2=incoming, 3=both, 4=manual
};

class MergeConflictEditor {
public:
    bool loadConflicts(const std::string& filePath);
    int getConflictCount() const;
    int getCurrentConflictIndex() const;
    ConflictHunk getCurrentConflict() const;
    void nextConflict();
    void previousConflict();
    void resolveCurrent(int resolution);
    std::string getResolvedContent() const;
    bool saveResolved(const std::string& outputPath = "");
    bool hasUnresolvedConflicts() const;
};

} // namespace Merge
} // namespace RawrXD
