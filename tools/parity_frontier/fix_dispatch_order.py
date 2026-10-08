#!/usr/bin/env python3
"""Surgical fail-closed repair: ensure activation allocation precedes Size().

Default = dry run.  --apply writes a timestamped backup and the patched file.
Only the two exact cases in PrimitiveDispatcher::Dispatch are touched.
"""
import argparse
import difflib
import pathlib
import sys
from datetime import datetime, timezone

OLD_TOPK = '''            case Primitive::TopKFwd: {
                const auto r=GenInput(op,0);
                return TopKFwd(getInput(op,0),getOutput(op),arena.Size(r.id),arena.Size(op.output.id));
            }'''
NEW_TOPK = '''            case Primitive::TopKFwd: {
                const auto r = GenInput(op, 0);
                // getOutput() allocates the activation. Function arguments have
                // unspecified evaluation order, so never query Size() in the same call.
                const float* input = getInput(op, 0);
                float* output = getOutput(op);
                const size_t inputN = arena.Size(r.id);
                const size_t outputN = arena.Size(op.output.id);
                if (!input || !output || inputN != GEN::ModelConfig::kExpertCount ||
                    outputN != 2u * GEN::ModelConfig::kExpertUsedCount) {
                    std::fprintf(stderr,
                        "[IR] TOPK_BIND_FAIL op=%u inputN=%zu outputN=%zu input=%d output=%d\\n",
                        op.opId, inputN, outputN, input != nullptr, output != nullptr);
                    return false;
                }
                return TopKFwd(input, output, inputN, outputN);
            }'''
OLD_MOE = '''            case Primitive::MoEExecuteFwd: {
                const auto a=GenInput(op,0),b=GenInput(op,1);
                return MoEExecuteFwd(getInput(op,0),getInput(op,1),getOutput(op),
                                     op,romResolver,arena.Size(a.id),arena.Size(b.id),
                                     arena.Size(op.output.id));
            }'''
NEW_MOE = '''            case Primitive::MoEExecuteFwd: {
                const auto a = GenInput(op, 0), b = GenInput(op, 1);
                const float* input = getInput(op, 0);
                const float* choices = getInput(op, 1);
                // ResolveOutput must run before any output Size query.
                float* output = getOutput(op);
                const size_t inputN = arena.Size(a.id);
                const size_t choicesN = arena.Size(b.id);
                const size_t outputN = arena.Size(op.output.id);
                if (!input || !choices || !output ||
                    inputN != GEN::ModelConfig::kEmbeddingLength ||
                    choicesN != 2u * GEN::ModelConfig::kExpertUsedCount ||
                    outputN != GEN::ModelConfig::kEmbeddingLength) {
                    std::fprintf(stderr,
                        "[IR] MOE_BIND_FAIL op=%u inputN=%zu choicesN=%zu outputN=%zu "
                        "input=%d choices=%d output=%d\\n",
                        op.opId, inputN, choicesN, outputN,
                        input != nullptr, choices != nullptr, output != nullptr);
                    return false;
                }
                return MoEExecuteFwd(input, choices, output, op, romResolver,
                                     inputN, choicesN, outputN);
            }'''

def patch(src: str):
    a, b = src.count(OLD_TOPK), src.count(OLD_MOE)
    if a == 0 and b == 0 and src.count(NEW_TOPK) == 1 and src.count(NEW_MOE) == 1:
        return src, 'ALREADY_PATCHED'
    if a != 1 or b != 1 or src.count(NEW_TOPK) or src.count(NEW_MOE):
        raise ValueError(f'REJECTED: expected one original case each, got TopK={a} MoE={b}. Partial/changed source preserved.')
    out = src.replace(OLD_TOPK, NEW_TOPK).replace(OLD_MOE, NEW_MOE)
    if out.count('TOPK_BIND_FAIL') != 1 or out.count('MOE_BIND_FAIL') != 1:
        raise ValueError('REJECTED: post-edit assertion failed')
    return out, 'PATCH_READY'

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('source', type=pathlib.Path)
    ap.add_argument('--apply', action='store_true')
    args = ap.parse_args()
    if not args.source.is_file():
        sys.exit(f'SOURCE_MISSING: {args.source}')
    old = args.source.read_bytes()
    # Read / write bytes in UTF-8 to preserve LF/CRLF when replacing the exact cases.
    decoded = old.decode('utf-8-sig')
    newline = '\r\n' if b'\r\n' in old else '\n'
    canon = decoded.replace('\r\n', '\n')
    try:
        new, status = patch(canon)
    except ValueError as exc:
        sys.exit(str(exc))
    print(f'SOURCE={args.source}\nPATCH_STATUS={status}')
    if status == 'ALREADY_PATCHED':
        return
    diff = difflib.unified_diff(canon.splitlines(),new.splitlines(),fromfile='before',tofile='after',lineterm='')
    print('\n'.join(diff))
    if not args.apply:
        print('DRY_RUN_ONLY=1')
        return
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup = args.source.with_name(args.source.name + '.pre_dispatch_order_' + stamp + '.bak')
    if backup.exists():
        sys.exit('BACKUP_CONFLICT: refuse to overwrite existing backup')
    backup.write_bytes(old)
    payload = new.replace('\n', newline).encode('utf-8')
    if old.startswith(b'\xef\xbb\xbf'):
        payload = b'\xef\xbb\xbf' + payload
    args.source.write_bytes(payload)
    print(f'BACKUP={backup}\nPATCH_APPLIED=1')

if __name__ == '__main__':
    main()
