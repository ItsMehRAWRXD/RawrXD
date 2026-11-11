import json, os

d = r'F:\rawrxd\evidence\RAWRXD_DEEP2_RUNTIME_IR_BINDING_001'
os.makedirs(d, exist_ok=True)

cert = {
    'certificate_id': 'RAWRXD_DEEP2_RUNTIME_IR_BINDING_001',
    'date': '2026-10-11',
    'verdict': 'BLOCKED',

    'goal': 'Bind the runtime IR bridge to a real validated GGUF and produce real '
            'prefill logits through a runtime-generated execution graph.',

    'what_was_established': {
        'architecture_identity': 'The executor\'s generated ModelConfig matches '
            'deepseek-coder-v2-16b on every dimension: 27 blocks, embedding 2048, '
            'vocab 102400, context 163840, 16 heads, rope dim 64, 64 experts, top-6, '
            '2 shared, expert FFN 1408, and kLeadingDenseBlocks 1 matching the observed '
            '1 dense plus 26 MoE block split. kTensorCount 377 matches the file.',
        'tensor_name_identity': 'All 377 tensor names in TensorROM.generated.hpp are present '
            'in the GGUF, and no GGUF tensor is absent from the table. The one non-matching '
            'quoted string is a header include, not a tensor.',
        'block_structure_identity': 'deep2_plan confirms 27 blocks, 26 MoE, 1 dense, and '
            'the dense block is block 0 with ffn_down, ffn_gate and ffn_up while blocks 1 to '
            '26 carry ffn_gate_exps, ffn_up_exps, ffn_down_exps, ffn_gate_inp and the three '
            'shared-expert tensors.',
        'loader_fix': 'The build failed to link because src/deep2/quant_dot_dispatch.cpp, which '
            'implements RawrXD::Deep2::QuantDot, was not in compile_ir_executor.bat. Adding it '
            'resolves three unresolved externals and the executable builds.'
    },

    'the_blocker': {
        'summary': 'ROMResolver::Resolve validates each tensor against the generated '
                   'kTensorROMTable by name, dtype, offset, encoded bytes, rank and dims. '
                   'For this model the name set matches but the dtype and byte offset do not, '
                   'so every lookup returns nullptr and all logits are zero.',
        'evidence': {
            'rom_expects': {'name': 'token_embd.weight', 'dtype': 'F16', 'offset': 172032000, 'bytes': 117964800, 'rank': 2},
            'file_has':    {'name': 'token_embd.weight', 'dtype': 'Q4_0', 'offset': 176028128, 'bytes': 117964800, 'rank': 2},
            'observed': 'LOGITS_FINITE=1 but LOGITS_FINITE is vacuous: max logit is 0.000000 and '
                        'PREDICTED_TOKEN=0. The resolver printed [ROM_DBG] id=1 showing the '
                        'dtype and offset mismatch.'
        },
        'why': ('TensorROM.generated.hpp, ModelConfig.generated.hpp and ExecutionIR.generated.hpp '
                'were generated for a model whose tensor inventory, ordering and dtypes differ from '
                'deepseek-coder-v2-16b. A matching name set is not sufficient: ROM resolution is '
                'offset- and dtype-exact by design, which is the right fail-closed behaviour. '
                "The naming 'DeepSeek-V2-Lite-Chat' does not imply shape identity."),
        'consequence': 'This is not a kernel bug and not a reader bug. The generated tables must be '
                       'regenerated for this model before it can run.'
    },

    'what_would_unblock_it': [
        'A generator that emits ModelConfig.generated.hpp, TensorROM.generated.hpp and '
        'ExecutionIR.generated.hpp from a GGUF read through RawrXDGgufReader, consuming '
        'QuantTypeTable for block geometry.',
        'The bridge already supplies the inputs: architecture, block kind schedule, dense versus '
        'MoE block split, and per-tensor name, dtype, dims, absolute offset and byte count.',
        'The execution graph construction is already exercisable: deep2bridge::build correctly '
        'rejects this model today with MoE-kernel-unavailable because routed-MoE dispatch is '
        'not wired, which is the second gate after table regeneration.'
    ],

    'status_of_the_a_b_test': {
        'reader': 'PASS, 56 of 56 files, 26829 of 26829 tensors validated',
        'plan_bridge': 'PASS, 56 of 56 files classified into four families',
        'runtime_ir_construction': 'PASS standalone, layers=27 dense=1 moe=26 nodes=241',
        'runtime_ir_binding_to_real_model': 'BLOCKED by generated-table mismatch'
    },

    'what_is_not_claimed': [
        'No logits, tokens, TPS or parity result for deepseek-coder-v2-16b. The single-token run '
        'produced zero-valued logits because no tensor resolved.',
        'No successful generation through a runtime-generated execution graph.',
        'The QUANTDOT_VERDICT=NOT_GPU observed in the run is expected: no GPU kernel is enabled '
        'by default and the CPU path is the certified default.'
    ],

    'reproduction': {
        'binding_tool': 'tools/deep2_runtime_ir.cpp, built by tools/build_runtime_ir.bat',
        'bridge_under_test': 'Deep2_RuntimeIRBridge/include/RuntimeIRBridge.hpp',
        'build_fix': 'compile_ir_executor.bat now compiles src/deep2/quant_dot_dispatch.cpp',
        'run': 'modelgenie_ir_executor.exe <gguf> <evidence_dir>  (set RAWRXD_ROM_TRACE=1 for '
               'the resolver diagnostic)'
    },
}

p = os.path.join(d, 'certificate.json')
json.dump(cert, open(p, 'w'), indent=2)
print('Wrote', p)
print('verdict:', cert['verdict'])
