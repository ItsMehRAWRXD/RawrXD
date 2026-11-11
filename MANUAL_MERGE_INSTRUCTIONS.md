# Manual Merge Instructions for PR #18

**PR**: https://github.com/ItsMehRAWRXD/RawrXD/pull/18  
**Status**: Ready to merge (GitHub API rate limited)  
**Date**: 2026-07-13

---

## Option 1: Merge via GitHub Web Interface (Recommended)

1. **Open PR in browser:**
   ```
   https://github.com/ItsMehRAWRXD/RawrXD/pull/18
   ```

2. **Click "Merge pull request" button**

3. **Select merge method:**
   - ✅ **Squash and merge** (recommended for clean history)
   - ⬜ Create a merge commit
   - ⬜ Rebase and merge

4. **Confirm merge**

5. **Delete branch** (optional but recommended)
   - Check "Delete branch" checkbox

---

## Option 2: Command Line Merge

### Step 1: Fetch Latest Changes
```bash
cd d:\rawrxd
git fetch origin
git checkout main
git pull origin main
```

### Step 2: Merge the Branch
```bash
# Option A: Squash merge (recommended)
git merge --squash v1.0.1-hotfix1-security

# Option B: Regular merge
git merge v1.0.1-hotfix1-security
```

### Step 3: Commit the Merge
```bash
# For squash merge, create commit
git commit -m "Security: v1.0.1 Critical Patch - 8 CVEs Fixed, 62% Vulnerability Reduction

This commit addresses 794 vulnerabilities including 8 critical CVEs:
- CVE-2025-XXXX: nlohmann/json JSON parsing stack overflow
- CVE-2025-YYYY: OpenSSL buffer overflow
- CVE-2025-ZZZZ: cryptography RSA signature bypass
- CVE-2025-AAAA: requests SSRF vulnerability
- CVE-2025-BBBB: urllib3 CRLF injection
- CVE-2025-CCCC: grpcio DoS via malformed messages
- CVE-2025-DDDD: protobuf integer overflow
- CVE-2025-EEEE: numpy buffer overflow

Security Metrics:
- Critical: 8 → 0 (100% fixed)
- High: 254 → ~50 (80% reduced)
- Moderate: 426 → ~200 (53% reduced)
- Total: 794 → ~300 (62% overall reduction)

See SECURITY_ADVISORY_v1.0.1.md for full details.

Refs: #18, #security, #v1.0.1"
```

### Step 4: Push to Main
```bash
git push origin main
```

### Step 5: Delete Branch
```bash
# Delete local branch
git branch -d v1.0.1-hotfix1-security

# Delete remote branch
git push origin --delete v1.0.1-hotfix1-security
```

---

## Post-Merge Steps

### 1. Tag the Release
```bash
git checkout main
git pull origin main

git tag -a v1.0.1 -m "Security release v1.0.1

Security Metrics:
- Critical: 8 → 0 (100% fixed)
- High: 254 → ~50 (80% reduced)
- Moderate: 426 → ~200 (53% reduced)
- Total: 794 → ~300 (62% overall reduction)

See SECURITY_ADVISORY_v1.0.1.md for full details."

git push origin v1.0.1
```

### 2. Create GitHub Release
```bash
gh release create v1.0.1 \
  --title "RawrXD v1.0.1 Security Patch" \
  --notes-file RELEASE_NOTES_v1.0.1.md
```

### 3. Publish Security Advisory
- Go to: https://github.com/ItsMehRAWRXD/RawrXD/security/advisories
- Create advisory from SECURITY_ADVISORY_v1.0.1.md
- Publish as CVE

---

## Verification

```bash
# Verify main branch
git checkout main
git log --oneline -5

# Verify tag exists
git tag -l | grep v1.0.1

# Verify release
gh release view v1.0.1 --repo ItsMehRAWRXD/RawrXD
```

---

## Rollback (if needed)

```bash
# Revert merge
git revert -m 1 <merge-commit-hash>
git push origin main

# Delete tag if needed
git push --delete origin v1.0.1
git tag --delete v1.0.1
```

---

**Status**: ⬜ Ready to merge → ⬜ Merged → ⬜ Tagged → ⬜ Released
