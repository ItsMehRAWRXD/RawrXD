"""RawrXD production receipt consistency checker; Python 3 stdlib only.
Does not modify source receipts or claim independent runtime certification.
Usage: py -3 cert_integrity.py F:\\rawrxd
"""
import json, pathlib, sys, re

GATES = {
 'RAWR_AUTONOMOUS_REPAIR_E2E_001': 'rawr_autonomous_repair',
 'HEXMAG_PARALLEL_WORKTREE_001': 'hexmag_parallel_worktree',
 'DEEP2_MULTIGPU_RESILIENCE_001': 'deep2_multigpu_resilience',
}

def main(root):
    ev = pathlib.Path(root) / 'evidence'
    certfile = ev / 'rawr_production_cert' / 'RAWR_PRODUCTION_CERT_001.json'
    try:
        cert = json.loads(certfile.read_text(encoding='utf-8-sig'))
    except (OSError, ValueError) as e:
        print('FAIL: cannot read production certificate:', e)
        return 1
    problems = []
    for gate in cert.get('evidence', {}).get('certified_gates', []):
        if gate not in GATES:
            problems.append(f'{gate}: no verified receipt mapping (fail closed)')
            continue
        path = ev / GATES[gate] / (gate + '.json')
        try:
            receipt = json.loads(path.read_text(encoding='utf-8-sig'))
        except (OSError, ValueError) as e:
            problems.append(f'{gate}: unreadable receipt: {e}')
            continue
        if receipt.get('gate') != gate or receipt.get('passed') is not True:
            problems.append(f'{gate}: receipt does not confirm PASS')
    digest = cert.get('release_manifest_sha256', '')
    if not isinstance(digest, str) or not re.fullmatch(r'[a-fA-F0-9]{64}', digest):
        problems.append('release manifest hash missing or malformed')
    # A well-formed hash is NOT proof that artifact bytes match it.
    if cert.get('passed') is True and problems:
        problems.append('PRODUCTION CERT CLAIM CONTRADICTS EVIDENCE')
    for issue in problems: print('FAIL:', issue)
    print('RECEIPT_CONSISTENCY=' + ('FAIL' if problems else 'PASS'))
    print('RUNTIME_CERTIFICATION=NOT_ASSESSED')
    return 1 if problems else 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else r'F:\rawrxd'))
