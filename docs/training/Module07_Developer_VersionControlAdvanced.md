# Sovereign IDE — Training Module 7
## Developer Path: Version Control Advanced

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Difficulty:** Intermediate  
**Duration:** 4 hours

---

## 1. Module Overview

This module covers advanced version control features in the Sovereign IDE. By the end of this module, you will be able to:

- Perform advanced Git operations
- Resolve merge conflicts
- Use Git history and blame
- Work with Git submodules
- Configure Git hooks and aliases

---

## 2. Advanced Git Operations

### 2.1 Interactive Rebase

**Start Interactive Rebase:**
```bash
# Rebase last 5 commits
git rebase -i HEAD~5

# Rebase onto specific branch
git rebase -i main
```

**Rebase Commands:**
- `pick` - Keep commit as-is
- `reword` - Edit commit message
- `edit` - Amend commit
- `squash` - Combine with previous
- `fixup` - Combine, discard message
- `drop` - Remove commit

**Sovereign IDE Integration:**
1. Source Control → ... → Rebase → Interactive Rebase
2. Select commits to modify
3. Choose action for each commit
4. Complete rebase

### 2.2 Cherry-Picking

**Cherry-Pick Commit:**
```bash
# Pick single commit
git cherry-pick abc123

# Pick without committing
git cherry-pick -n abc123

# Pick range
git cherry-pick abc123..def456
```

**IDE Workflow:**
1. Open Git History
2. Right-click commit
3. Select "Cherry-Pick Commit"
4. Resolve conflicts if needed

### 2.3 Stashing

**Stash Commands:**
```bash
# Stash changes
git stash push -m "WIP: feature X"

# Stash untracked files
git stash push -u

# List stashes
git stash list

# Apply stash
git stash apply stash@{0}

# Pop stash (apply and remove)
git stash pop stash@{0}

# Drop stash
git stash drop stash@{0}
```

**IDE Stash View:**
- View all stashes
- Apply/Pop/Drop stashes
- Diff stash contents

---

## 3. Merge Conflict Resolution

### 3.1 Conflict Markers

```cpp
<<<<<<< HEAD
void processData() {
    // Current implementation
    processFast();
=======
void processData() {
    // Incoming implementation
    processSecure();
>>>>>>> feature-branch
}
```

### 3.2 Merge Editor

**Open Merge Editor:**
1. Click conflicted file in Source Control
2. Select "Open Merge Editor"

**Three-Way View:**
```
┌──────────────┬──────────────┬──────────────┐
│   Current    │   Result     │   Incoming   │
│    (HEAD)    │              │   (Branch)   │
├──────────────┼──────────────┼──────────────┤
│              │              │              │
│   Your       │   Final      │   Their      │
│   Changes    │   Merged     │   Changes    │
│              │   Version    │              │
└──────────────┴──────────────┴──────────────┘
```

**Resolution Actions:**
- Accept Current
- Accept Incoming
- Accept Both
- Edit Result

### 3.3 Conflict Resolution Strategies

**Strategy: Ours vs Theirs**
```bash
# Checkout --ours (keep current)
git checkout --ours path/to/file

# Checkout --theirs (accept incoming)
git checkout --theirs path/to/file
```

**IDE Strategy Selection:**
1. Right-click conflicted file
2. Select resolution strategy
3. Mark as resolved

---

## 4. Git History and Blame

### 4.1 File History

**View File History:**
1. Right-click file → Open Timeline
2. Or: Git: View File History

**History Features:**
- Visual timeline
- Diff between versions
- Restore previous version
- Copy commit SHA

### 4.2 Git Blame

**Enable Blame:**
1. Right-click editor → Git: Toggle Blame
2. Or: Command Palette → Git: Toggle Blame Annotations

**Blame Information:**
```
Author     Date          Line  Code
John Doe   2 days ago    1     #include <iostream>
Jane Smith 1 week ago    2     using namespace std;
John Doe   2 days ago    3     
John Doe   2 days ago    4     int main() {
```

**Blame Actions:**
- Hover for commit details
- Click to open commit
- Compare with previous

### 4.3 Branch Comparison

**Compare Branches:**
1. Source Control → ... → Compare
2. Select base and compare branches
3. View diff

**Comparison View:**
- Files changed
- Commits ahead/behind
- Merge preview

---

## 5. Git Submodules

### 5.1 Submodule Basics

**Add Submodule:**
```bash
git submodule add https://github.com/user/repo.git libs/repo
```

**IDE Submodule Support:**
- Add submodule via UI
- Update submodules
- Initialize submodules

### 5.2 Submodule Operations

```bash
# Initialize submodules
git submodule update --init

# Update submodules
git submodule update --remote

# Clone with submodules
git clone --recurse-submodules <repo>

# Sync submodule URLs
git submodule sync
```

### 5.3 Submodule Configuration

**.gitmodules:**
```ini
[submodule "libs/repo"]
    path = libs/repo
    url = https://github.com/user/repo.git
    branch = main
```

---

## 6. Git Hooks

### 6.1 Hook Types

| Hook | Trigger | Use Case |
|------|---------|----------|
| `pre-commit` | Before commit | Run tests, lint |
| `prepare-commit-msg` | Before editor | Modify message |
| `commit-msg` | After message | Validate format |
| `post-commit` | After commit | Notifications |
| `pre-push` | Before push | Run CI checks |
| `post-merge` | After merge | Update deps |

### 6.2 Pre-Commit Hook Example

**.git/hooks/pre-commit:**
```bash
#!/bin/bash

# Run linter
make lint
if [ $? -ne 0 ]; then
    echo "Linting failed. Commit aborted."
    exit 1
fi

# Run tests
make test
if [ $? -ne 0 ]; then
    echo "Tests failed. Commit aborted."
    exit 1
fi

exit 0
```

### 6.3 IDE Hook Integration

**Configure in Settings:**
```json
{
    "git.hooksPath": ".githooks",
    "git.enableCommitSigning": true
}
```

---

## 7. Git Aliases

### 7.1 Configuring Aliases

**Global Aliases:**
```bash
# Short status
git config --global alias.st status

# Pretty log
git config --global alias.lg "log --oneline --graph --decorate"

# Undo last commit
git config --global alias.undo "reset --soft HEAD~1"

# Amend commit
git config --global alias.amend "commit --amend --no-edit"
```

### 7.2 Useful Aliases

```bash
# View all aliases
git config --get-regexp alias

# Common workflow aliases
git config --global alias.co checkout
git config --global alias.br branch
git config --global alias.ci commit
git config --global alias.st status

# Advanced aliases
git config --global alias.last "log -1 HEAD"
git config --global alias.visual "!gitk"
git config --global alias.squash "!git rebase -i HEAD~"
```

---

## 8. Practical Exercises

### Exercise 1: Interactive Rebase

**Objective:** Clean up commit history

**Tasks:**
1. Create 5 commits with messages
2. Start interactive rebase
3. Squash 3 commits into 1
4. Reword commit messages
5. Complete rebase

**Expected Time:** 25 minutes

### Exercise 2: Merge Conflict Resolution

**Objective:** Resolve merge conflicts

**Tasks:**
1. Create two branches with conflicting changes
2. Attempt merge
3. Open merge editor
4. Resolve conflicts
5. Complete merge

**Expected Time:** 30 minutes

### Exercise 3: Git Blame Analysis

**Objective:** Analyze code history

**Tasks:**
1. Open a source file
2. Enable blame annotations
3. Find who last modified each line
4. View commit details
5. Compare with previous version

**Expected Time:** 20 minutes

### Exercise 4: Submodule Management

**Objective:** Work with submodules

**Tasks:**
1. Add a submodule
2. Make changes in submodule
3. Update parent repository
4. Clone repository with submodules

**Expected Time:** 25 minutes

---

## 9. Module Assessment

### Knowledge Check

1. What is interactive rebase used for?
2. How do you resolve merge conflicts in the IDE?
3. What information does git blame provide?
4. How do you add a submodule?
5. What is the purpose of pre-commit hooks?

### Practical Assessment

Complete advanced Git workflow:
1. Perform interactive rebase
2. Resolve merge conflicts
3. Use git blame
4. Configure a Git hook
5. Create Git aliases

**Pass Criteria:** Successfully complete all exercises

---

## 10. Next Steps

Upon completing this module:

1. Proceed to **Module 8: Developer Path - Extensions**
2. Practice advanced Git workflows
3. Set up hooks for your projects
4. Learn about Git workflows (GitFlow, trunk-based)

---

## Summary

This module covered:

- ✅ Advanced Git operations
- ✅ Merge conflict resolution
- ✅ Git history and blame
- ✅ Git submodules
- ✅ Git hooks
- ✅ Git aliases

**Status:** Complete

---

*End of Module 7: Developer Path - Version Control Advanced*
