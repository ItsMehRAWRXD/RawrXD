#!/usr/bin/env python3
"""Apply pseudo-unified-diff patches where @@ headers have no line numbers.

v9: v8 + token-level matching for whitespace/line-break drift.

New in v9:
  - anchor_matches gains a token mode: compare with ALL whitespace
    removed.  'e.type = type;' == 'e.type=type;', and a line split across
    a source line break can be joined with following lines.
  - try_match, on failing a context/remove entry, tries to satisfy it by
    consuming 2..MAX_JOIN source lines whose joined tokens equal the
    entry tokens (line-break drift), preserving the original source lines.
  - remove entries also get bounded lookahead like context entries (the
    author's file may have unrelated members between the anchor and the
    removed member).
"""
import sys, os, glob, re

LOOKAHEAD_MAX = 250
JOIN_MAX = 4
PENALTY_PASSTHROUGH = 3
PENALTY_SKIPPABLE = 1
PENALTY_SPLIT = 5
PENALTY_WS_DRIFT = 2
PENALTY_JOIN = 4
PENALTY_BEFORE_CURSOR = 40
MAX_SPLIT_DEPTH = 3
MAX_SPLITS = 12
FUZZ_WARN = 9

def read_patch(path):
    with open(path, 'r', encoding='utf-8', newline='') as f:
        text = f.read()
    return text.replace('\r\n', '\n').split('\n')

def parse_patch(lines):
    sections = []
    ei = 0
    n = len(lines)
    while ei < n:
        if 'diff --git' in lines[ei] and re.match(r'\s*diff --git', lines[ei]):
            m = re.match(r'\s*diff --git a/(.*?) b/(.*?)(?: .*)?$', lines[ei])
            file_b = m.group(2).strip() if m else None
            ei += 1
            file_a = None
            while ei < n and not lines[ei].lstrip().startswith('@@'):
                if lines[ei].startswith('--- a/'):
                    file_a = lines[ei][6:].strip()
                elif lines[ei].startswith('+++ b/'):
                    file_b = lines[ei][6:].strip()
                ei += 1
            hunks = []
            while ei < n and not re.match(r'\s*diff --git', lines[ei]):
                if lines[ei].lstrip().startswith('@@'):
                    ei += 1
                    hunk = []
                    while ei < n and not (lines[ei].lstrip().startswith('@@') or
                                          re.match(r'\s*diff --git', lines[ei])):
                        hunk.append(lines[ei])
                        ei += 1
                    if hunk:
                        hunks.append(hunk)
                else:
                    ei += 1
            sections.append((file_a, file_b, hunks))
        else:
            ei += 1
    return sections

def parse_entries(hunk):
    entries = []
    for hl in hunk:
        if hl.startswith('---') or hl.startswith('+++'):
            continue
        if hl.startswith('+'):
            entries.append(('add', hl[1:]))
        elif hl.startswith('-'):
            entries.append(('remove', hl[1:]))
        elif hl.startswith(' ') or hl.startswith('\t'):
            entries.append(('context', hl[1:] if hl[0] in ' \t' else hl))
        else:
            entries.append(('context', hl))
    return entries

def is_skippable_source(line):
    s = line.strip()
    if not s:
        return True
    if s.startswith('//') or s.startswith('/*') or s.startswith('*'):
        return True
    return False

def line_eq(a, b):
    return a.rstrip() == b.rstrip()

def collapse_ws(s):
    return ' '.join(s.split())

def tok(s):
    return ''.join(s.split())

def anchor_matches(fl_line, anchor):
    """Return match quality 0(exact) 1(strip) 2(collapsed) 3(token) or None."""
    if line_eq(fl_line, anchor):
        return 0
    if fl_line.strip() == anchor.strip():
        return 1
    if collapse_ws(fl_line) == collapse_ws(anchor):
        return 2
    if tok(fl_line) == tok(anchor):
        return 3
    return None

def try_match(file_lines, entries, start_si):
    """Align entries against file_lines starting at start_si.

    Returns (end_si, out, fuzz, fail_ei); fail_ei is None on success.
    """
    out = []
    si = start_si
    ei = 0
    ne = len(entries)
    fuzz = 0

    while ei < ne:
        kind, text = entries[ei]

        if kind == 'add':
            out.append(text)
            ei += 1
            continue

        if si < len(file_lines):
            q = anchor_matches(file_lines[si], text)
            if q is not None:
                if kind == 'context':
                    out.append(file_lines[si])
                fuzz += q * PENALTY_WS_DRIFT if q else 0
                si += 1
                ei += 1
                continue

            # token-join: entry text spans multiple source lines
            joined_ok = False
            if tok(text):
                for k in range(1, JOIN_MAX + 1):
                    if si + k >= len(file_lines):
                        break
                    joined = '\n'.join(file_lines[si:si + k + 1])
                    if tok(joined) == tok(text):
                        if kind == 'context':
                            out.extend(file_lines[si:si + k + 1])
                        si += k + 1
                        ei += 1
                        fuzz += PENALTY_JOIN * k
                        joined_ok = True
                        break
            if joined_ok:
                continue

        # skippable source line
        if si < len(file_lines) and is_skippable_source(file_lines[si]):
            out.append(file_lines[si])
            si += 1
            fuzz += PENALTY_SKIPPABLE
            continue

        # blank old-side line
        if not text.strip():
            if kind == 'context':
                out.append(text)
            ei += 1
            fuzz += PENALTY_SKIPPABLE
            continue

        # bounded lookahead passthrough (context AND remove)
        found = None
        limit = min(len(file_lines), si + LOOKAHEAD_MAX)
        for j in range(si + 1, limit):
            if anchor_matches(file_lines[j], text) is not None:
                found = j
                break
        if found is not None:
            out.extend(file_lines[si:found])
            fuzz += (found - si) * PENALTY_PASSTHROUGH
            si = found
            continue

        return None, None, None, ei

    return si, out, fuzz, None

def split_recursive(file_lines, entries, first_real, depth):
    anchor = entries[first_real][1]
    cands = []
    for si in range(len(file_lines)):
        q = anchor_matches(file_lines[si], anchor)
        if q is not None:
            cands.append((si, q))
    if not cands:
        return None, None
    best_out, best_score, fail_hint = None, None, None
    for si, q in sorted(cands, key=lambda c: (c[1], c[0])):
        end, out, fuzz, fail = try_match(file_lines, entries, si)
        if out is not None:
            score = fuzz + q
            if best_score is None or score < best_score:
                best_out = file_lines[:si] + out + file_lines[end:]
                best_score = score
        elif fail is not None and fail_hint is None and fail > first_real:
            fail_hint = fail
    if best_out is not None:
        return best_out, best_score

    if depth >= MAX_SPLIT_DEPTH:
        return None, None

    splits = []
    if fail_hint is not None and fail_hint > first_real and \
            entries[fail_hint][0] == 'context':
        splits.append(fail_hint)
    for i in range(first_real + 1, len(entries)):
        if entries[i][0] == 'context' and i not in splits:
            splits.append(i)
    for k in splits[:MAX_SPLITS]:
        part_old = [i for i, (k2, _) in enumerate(entries[:k]) if k2 != 'add']
        if not part_old:
            continue
        p1 = split_recursive(file_lines, entries[:k], 0, depth + 1)
        if p1[0] is None:
            continue
        p2 = split_recursive(p1[0], entries[k:], 0, depth + 1)
        if p2[0] is not None:
            return p2[0], p1[1] + p2[1] + PENALTY_SPLIT
    return None, None

def apply_hunk_ordered(file_lines, entries, cursor):
    old_idx = [i for i, (k, _) in enumerate(entries) if k != 'add']
    has_old = len(old_idx) > 0
    first_real = next((i for i in old_idx if entries[i][1].strip()), None) \
        if has_old else None

    if not has_old or first_real is None:
        texts = [t for k, t in entries if k == 'add']
        return file_lines[:cursor] + texts + file_lines[cursor:], \
               cursor + len(texts), 0

    anchor = entries[first_real][1]
    cands = []
    for si in range(cursor, len(file_lines)):
        q = anchor_matches(file_lines[si], anchor)
        if q is not None:
            cands.append((si, q))

    best_out, best_end, best_score = None, None, None
    for si, q in sorted(cands, key=lambda c: (c[1], c[0])):
        end, out, fuzz, fail = try_match(file_lines, entries, si)
        if out is not None:
            score = fuzz + q
            if best_score is None or score < best_score:
                best_out = file_lines[:si] + out + file_lines[end:]
                best_end = end
                best_score = score
    if best_out is None:
        for si in range(0, cursor):
            q = anchor_matches(file_lines[si], anchor)
            if q is None:
                continue
            end, out, fuzz, fail = try_match(file_lines, entries, si)
            if out is not None:
                score = fuzz + q + PENALTY_BEFORE_CURSOR
                if best_score is None or score < best_score:
                    best_out = file_lines[:si] + out + file_lines[end:]
                    best_end = end
                    best_score = score
    if best_out is None:
        return None, None, None
    return best_out, best_end, best_score

def apply_hunks(file_lines, hunks, file_label=''):
    cursor = 0
    total_fuzz = 0
    parsed = [parse_entries(h) for h in hunks]
    for hunk_idx, entries in enumerate(parsed):
        if not entries:
            continue

        old_idx = [i for i, (k, _) in enumerate(entries) if k != 'add']
        first_real = next(
            (i for i in old_idx if entries[i][1].strip()), None) \
            if old_idx else None
        has_change = any(k in ('add', 'remove') for k, _ in entries)

        if not has_change:
            # Context-only position marker: advance cursor.
            if first_real is None:
                continue
            anchor = entries[first_real][1]
            for si in range(cursor, len(file_lines)):
                q = anchor_matches(file_lines[si], anchor)
                if q is None:
                    continue
                end, out, fuzz, fail = try_match(file_lines, entries, si)
                if out is not None:
                    cursor = max(cursor, end)
                    total_fuzz += fuzz
                    break
            continue

        if not old_idx or first_real is None:
            # Pure-add hunk: insert before next hunk's first old-side anchor.
            next_anchor = None
            for j in range(hunk_idx + 1, len(parsed)):
                n_entries = parsed[j]
                n_old = [i for i, (k, _) in enumerate(n_entries)
                         if k != 'add']
                n_fr = next((i for i in n_old if n_entries[i][1].strip()),
                            None) if n_old else None
                if n_fr is not None:
                    next_anchor = n_entries[n_fr][1]
                    break
            insert_at = len(file_lines)
            if next_anchor is not None:
                for si in range(cursor, len(file_lines)):
                    if anchor_matches(file_lines[si], next_anchor) is not None:
                        insert_at = si
                        break
            texts = [t for k, t in entries if k == 'add']
            file_lines = (file_lines[:insert_at] + texts +
                          file_lines[insert_at:])
            cursor = insert_at + len(texts)
            continue

        result, end, fuzz = apply_hunk_ordered(file_lines, entries, cursor)
        if result is None:
            out2, fuzz2 = split_recursive(file_lines, entries, first_real, 0)
            if out2 is None:
                return None, hunks[hunk_idx]
            result = out2
            last_old = None
            for i in range(len(entries) - 1, -1, -1):
                if entries[i][0] != 'add' and entries[i][1].strip():
                    last_old = entries[i][1]
                    break
            end = cursor
            if last_old is not None:
                for si in range(cursor, len(result)):
                    if anchor_matches(result[si], last_old) is not None:
                        end = si + 1
                        break
            fuzz = fuzz2
        file_lines = result
        cursor = max(cursor, end)
        total_fuzz += fuzz
    return file_lines, total_fuzz

def apply_patch(patch_path, root_dir):
    lines = read_patch(patch_path)
    sections = parse_patch(lines)
    for file_a, file_b, hunks in sections:
        if not file_b:
            print('  [warn] no target path; skipped')
            continue
        rel = file_b
        for prefix in ('~dev/', './'):
            if rel.startswith(prefix):
                rel = rel[len(prefix):]
                break
        target = os.path.join(root_dir, rel)
        print(f'  {rel}')
        if not os.path.exists(target):
            adds = []
            for h in hunks:
                for hl in h:
                    if hl.startswith('+') and not hl.startswith('+++'):
                        adds.append(hl[1:])
            if adds:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, 'w', encoding='utf-8', newline='') as f:
                    f.write('\n'.join(adds) + ('\n' if adds else ''))
                continue
            print(f'  [error] target not found and no adds: {target}')
            return False
        with open(target, 'r', encoding='utf-8', newline='') as f:
            raw = f.read()
        norm = raw.replace('\r\n', '\n')
        trailing_nl = norm.endswith('\n')
        file_lines = norm.split('\n')
        if trailing_nl:
            file_lines = file_lines[:-1]
        result, fuzz = apply_hunks(file_lines, hunks, rel)
        if result is None:
            print(f'  [error] hunk failed on {rel}')
            return False
        if fuzz >= FUZZ_WARN:
            print(f'  [warn] {rel}: applied with fuzz={fuzz}')
        file_lines = result
        with open(target, 'w', encoding='utf-8', newline='') as f:
            f.write('\n'.join(file_lines) + ('\n' if trailing_nl or file_lines else ''))
    return True

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('patch', help='Patch file or glob')
    p.add_argument('root', help='Project root directory')
    args = p.parse_args()
    if any(c in args.patch for c in '*?['):
        patches = sorted(glob.glob(args.patch))
        if not patches:
            print(f'No patches matched: {args.patch}')
            sys.exit(1)
    else:
        patches = [args.patch]
    for pth in patches:
        print(f'=== {os.path.basename(pth)} ===')
        if not apply_patch(pth, args.root):
            print(f'FAILED: {pth}')
            sys.exit(1)
    print('All patches applied.')
