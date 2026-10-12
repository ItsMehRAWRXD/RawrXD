from pathlib import Path

# Check tools directory for comparison scripts
tools_dir = Path(r'F:/rawrxd/tools')
if tools_dir.exists():
    py_files = sorted(tools_dir.glob('*.py'))
    print(f'tools/*.py ({len(py_files)}):')
    for f in py_files:
        print(f'  {f.name}')

# Check for any certificate scripts in evidence
evidence_dir = Path(r'F:/rawrxd/evidence/RAWRXD_REFERENCE_REPRODUCIBILITY_001')
scripts = sorted(evidence_dir.rglob('*.py')) + sorted(evidence_dir.rglob('*.bat')) + sorted(evidence_dir.rglob('*.sh'))
print(f'\nReproducibility evidence scripts ({len(scripts)}):')
for s in scripts:
    print(f'  {s.relative_to(evidence_dir)}')

# Check endurace log
endurance = evidence_dir / 'endurance_512.log'
if endurance.exists():
    print(f'\nEndurance log exists: {endurance.stat().st_size} bytes')
    content = endurance.read_text()[:2000]
    print(content[:500])

# Check divergence forensics
divergence = evidence_dir / 'divergence_forensics.md'
if divergence.exists():
    print(f'\nDivergence forensics exists')
    content = divergence.read_text()[:3000]
    print(content[:3000])
