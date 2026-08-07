// ============================================================================
// merge_conflict_editor.cpp — Visual 3-Way Merge Conflict Editor
// ============================================================================

#include <string>
#include <vector>
#include <fstream>
#include <sstream>

namespace RawrXD {
namespace Merge {

struct ConflictHunk {
    int startLine;
    int endLine;
    std::string ancestor;    // Common ancestor (base)
    std::string current;     // Current branch (HEAD)
    std::string incoming;    // Incoming branch (MERGE_HEAD)
    int resolution;          // 0=unresolved, 1=current, 2=incoming, 3=both, 4=manual
};

class MergeConflictEditor {
private:
    std::string filePath_;
    std::vector<ConflictHunk> conflicts_;
    int currentConflictIndex_ = 0;
    
public:
    bool loadConflicts(const std::string& filePath) {
        filePath_ = filePath;
        conflicts_.clear();
        
        std::ifstream file(filePath);
        if (!file) return false;
        
        std::string line;
        int lineNum = 0;
        ConflictHunk currentHunk;
        bool inConflict = false;
        enum class Section { None, Ancestor, Current, Incoming } currentSection = Section::None;
        
        while (std::getline(file, line)) {
            lineNum++;
            
            if (line == "<<<<<<< HEAD") {
                inConflict = true;
                currentHunk.startLine = lineNum;
                currentSection = Section::Current;
                continue;
            }
            
            if (line == "=======" && inConflict) {
                currentSection = Section::Incoming;
                continue;
            }
            
            if (line.starts_with(">>>>>>> ") && inConflict) {
                currentHunk.endLine = lineNum;
                conflicts_.push_back(currentHunk);
                inConflict = false;
                currentSection = Section::None;
                continue;
            }
            
            if (line.starts_with("||||||| ")) {
                currentSection = Section::Ancestor;
                continue;
            }
            
            if (inConflict) {
                switch (currentSection) {
                    case Section::Ancestor:
                        currentHunk.ancestor += line + "\n";
                        break;
                    case Section::Current:
                        currentHunk.current += line + "\n";
                        break;
                    case Section::Incoming:
                        currentHunk.incoming += line + "\n";
                        break;
                    default:
                        break;
                }
            }
        }
        
        return !conflicts_.empty();
    }
    
    int getConflictCount() const { return conflicts_.size(); }
    int getCurrentConflictIndex() const { return currentConflictIndex_; }
    
    ConflictHunk getCurrentConflict() const {
        if (currentConflictIndex_ >= conflicts_.size()) {
            return ConflictHunk();
        }
        return conflicts_[currentConflictIndex_];
    }
    
    void nextConflict() {
        if (currentConflictIndex_ < conflicts_.size() - 1) {
            currentConflictIndex_++;
        }
    }
    
    void previousConflict() {
        if (currentConflictIndex_ > 0) {
            currentConflictIndex_--;
        }
    }
    
    void resolveCurrent(int resolution) {
        if (currentConflictIndex_ >= conflicts_.size()) return;
        conflicts_[currentConflictIndex_].resolution = resolution;
    }
    
    std::string getResolvedContent() const {
        std::ifstream file(filePath_);
        if (!file) return "";
        
        std::stringstream result;
        std::string line;
        int lineNum = 0;
        size_t conflictIdx = 0;
        
        while (std::getline(file, line)) {
            lineNum++;
            
            if (conflictIdx < conflicts_.size() && lineNum == conflicts_[conflictIdx].startLine) {
                // Skip conflict markers and output resolved content
                const auto& conflict = conflicts_[conflictIdx];
                
                switch (conflict.resolution) {
                    case 1: // Current
                        result << conflict.current;
                        break;
                    case 2: // Incoming
                        result << conflict.incoming;
                        break;
                    case 3: // Both
                        result << conflict.current << conflict.incoming;
                        break;
                    case 4: // Manual (already in file)
                        break;
                    default: // Unresolved - keep markers
                        result << "<<<<<<< HEAD\n";
                        result << conflict.current;
                        result << "=======\n";
                        result << conflict.incoming;
                        result << ">>>>>>> incoming\n";
                        break;
                }
                
                // Skip to end of conflict
                while (lineNum < conflict.endLine && std::getline(file, line)) {
                    lineNum++;
                }
                
                conflictIdx++;
                continue;
            }
            
            result << line << "\n";
        }
        
        return result.str();
    }
    
    bool saveResolved(const std::string& outputPath = "") {
        std::string content = getResolvedContent();
        if (content.empty()) return false;
        
        std::string targetPath = outputPath.empty() ? filePath_ : outputPath;
        std::ofstream file(targetPath);
        if (!file) return false;
        
        file << content;
        return true;
    }
    
    bool hasUnresolvedConflicts() const {
        for (const auto& conflict : conflicts_) {
            if (conflict.resolution == 0) return true;
        }
        return false;
    }
};

} // namespace Merge
} // namespace RawrXD
