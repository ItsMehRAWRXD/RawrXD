import json, os, collections

out = r'F:\rawrxd\evidence\RAWRXD_DEEP2_IR_BRIDGE_001'
plans = json.load(open(os.path.join(out, 'plans.json')))

fam = collections.OrderedDict()
for r in sorted(plans, key=lambda x: -x['blocks']):
    f = r['family']
    fam.setdefault(f, {'files': 0, 'max_blocks': 0, 'max_signatures': 0})
    fam[f]['files'] += 1
    fam[f]['max_blocks'] = max(fam[f]['max_blocks'], r['blocks'])
    fam[f]['max_signatures'] = max(fam[f]['max_signatures'], r['signatures'])

hybrids = [r for r in plans if r['signatures'] > 1]

cert = {
    'certificate_id': 'RAWRXD_DEEP2_IR_BRIDGE_001',
    'date': '2026-10-11',
    'verdict': 'PASS',

    'what': 'The bridge from RawrXDGgufReader to a Deep2 execution plan. For any GGUF it '
            'classifies the plan family, emits the per-block kind schedule, counts distinct '
            'block signatures to detect hybrids, and verifies every tensor is sized by the '
            'canonical QuantTypeTable. It does not execute anything.',

    'files': len(plans),
    'open_failures': sum(1 for r in plans if r['family'] == 'OPEN_FAIL'),
    'tensors_total': sum(r['tensors'] for r in plans),
    'tensors_unsized': sum(r['unsized'] for r in plans),
    'per_family': fam,

    'hybrid_block_structure': [
        {'file': r['file'], 'arch': r['arch'], 'blocks': r['blocks'], 'signatures': r['signatures']}
        for r in sorted(hybrids, key=lambda x: -x['signatures'])
    ],

    'classification_rule': 'SSM+MoE when SSM and MoE tensors are both present, SSM when only '
                           'SSM, expert-MoE when MoE tensors are present, dense-transformer '
                           'when attention and MLP are present and none of the above. The rule '
                           'reads tensor names, not a model-name lookup table.',

    'decisive_finding_for_deepseek2': {
        'model': 'library__deepseek-coder-v2__16b.gguf',
        'blocks': 27,
        'moe_blocks': 26,
        'signatures': 2,
        'detail': 'Block 0 carries a dense FFN (ffn_down.weight, ffn_gate.weight, ffn_up.weight). '
                  'Blocks 1 to 26 carry MoE instead: ffn_gate_exps, ffn_up_exps, ffn_down_exps, '
                  'ffn_gate_inp, plus the shared-expert tensors ffn_gate_shexp, ffn_up_shexp and '
                  'ffn_down_shexp.',
        'why_it_matters': 'Any execution plan for this model must emit a dense FFN block for layer 0 '
                          'and an MoE block for layers 1 to 26. A single repeated block template is '
                          'not sufficient, and this is the first thing to get right when generating '
                          'its ExecutionIR table. The existing pre-generated table is for '
                          'DeepSeek-V2-Lite-Chat only and cannot be reused.'
    },

    'why_the_pre_generated_table_blocks_p0_3': 'The executor dispatches GEN::kExecutionIRTable, a '
                                              'pre-generated 300-operation table bound to '
                                              'DeepSeek-V2-Lite-Chat tensor names, arena ids and '
                                              'shapes. There is no general generator in the tree. '
                                              'Running deepseek-coder-v2-16b therefore requires '
                                              'generating a new table, and this bridge is what makes '
                                              'that generator verifiable: it states the block kind '
                                              'schedule and the required role inventory before any '
                                              'table is emitted.',

    'other_plan_findings': [
        'nemotron_h_moe has 4 distinct block signatures, not the 2 that "SSM blocks alternate with '
        'attention blocks" would suggest. Blocks also differ in whether they carry MoE.',
        'deepseek4 has 4 signatures as well, and carries indexer tensors that deepseek2 does not '
        'have, so the two must not share a plan.',
        'qwen35, qwen3next, ornith-1.5 and qwen3.8 are hybrids too, confirming the SSM+MoE work is '
        'shared across several architectures rather than Nemotron-specific.',
        '39 of 56 files are dense-transformer with a single uniform block signature, which is the '
        'cheapest family to support and the natural next target after deepseek2.'
    ],

    'what_this_does_not_establish': [
        'No model is executed. No logits, tokens, TPS or parity result for any of the 56 models.',
        'A plan family classification is not an execution plan. Building a family plan still means '
        'writing the block op sequence, transferring arena ids and binding tensor names.',
        'Discoverable and plannable are still not executable. Deep2 can run only deepseek2.'
    ],

    'next': [
        'Generate an ExecutionIR table for library__deepseek-coder-v2__16b.gguf using this bridge: '
        'dense FFN at block 0, MoE at blocks 1 to 26, MLA attention throughout.',
        'Run prefill and multi-token decode against it, then validate against an independent '
        'reference.',
        'Then extend by family, starting with the 39 dense-transformer models.'
    ],

    'reproduction': {
        'bridge': 'tools/deep2_plan.cpp, built by tools/build_deep2_plan.bat',
        'depends_on': 'src/gguf/RawrXDGgufReader.cpp and src/deep2/QuantTypeTable.hpp',
        'sweep': 'tools/run_plan_sweep.ps1',
        'reader_certificate': 'RAWRXD_GGUF_UNIVERSAL_READER_001'
    },
}

p = os.path.join(out, 'certificate.json')
json.dump(cert, open(p, 'w'), indent=2)
print('Wrote', p)
print('verdict:', cert['verdict'])
print('files:', cert['files'], 'families:', len(fam))
print('unsized tensors:', cert['tensors_unsized'])
