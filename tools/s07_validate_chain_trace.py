"""Validate saved S07 chain diagnostics against independent greedy token output.

CPU-only. No model loading, runtime execution, or GPU use. Print JSON to stdout.
Executor Position() is the position of the last executed token, not the next one.
"""
import argparse
import json
import re
import sys
from pathlib import Path


def read_text(path):
    data = Path(path).read_bytes()
    return data.decode('utf-16' if data[:2] in (b'\xff\xfe', b'\xfe\xff') else 'utf-8-sig')


def validate(trace, baseline, min_ngram=3):
    errors = []
    warnings = []
    counts = {'proposed': 0, 'accepted': 0, 'rejected': 0, 'discarded': 0,
              'verified': 0, 'chains': 0}

    def expect(condition, where, message):
        if not condition:
            errors.append({'location': where, 'message': message})

    def integer(value):
        return isinstance(value, int) and not isinstance(value, bool)

    if not isinstance(trace, dict):
        return {'valid': False, 'errors': [{'location': 'root', 'message': 'trace must be an object'}]}
    prefill = trace.get('prefill_tokens')
    expect(integer(prefill) and prefill == 32, 'prefill_tokens', 'expected deterministic 32-token prompt')
    if not integer(prefill) or prefill < 1:
        return {'valid': False, 'errors': errors}
    prompt = [1 + (i * 37) % 1000 for i in range(prefill)]
    full = prompt + baseline
    forward_calls = trace.get('target_decode_forward_calls')
    expect(integer(forward_calls), 'target_decode_forward_calls', 'must be an integer')
    expect(forward_calls == len(baseline), 'target_decode_forward_calls',
           f'serial verification must report {len(baseline)} decode forwards')
    chains = trace.get('chains')
    if not isinstance(chains, list):
        errors.append({'location': 'chains', 'message': 'must be an array'})
        return {'valid': False, 'errors': errors}
    counts['chains'] = len(chains)
    if min_ngram == 3:
        expect(bool(chains), 'chains', 'expected first minimum-three chain at context position 88')
        if chains and isinstance(chains[0], dict):
            expect(chains[0].get('context_size') == 88, 'chains[0].context_size',
                   'expected first minimum-three chain at context position 88')
            expect(chains[0].get('matched_length') == 3, 'chains[0].matched_length',
                   'expected first matched ngram length 3')
    previous_context = None
    previous_end = None
    previous_number = None
    for index, chain in enumerate(chains):
        where = f'chains[{index}]'
        if not isinstance(chain, dict):
            errors.append({'location': where, 'message': 'must be an object'})
            continue
        chain_number = chain.get('chain')
        context_size = chain.get('context_size')
        matched_start = chain.get('matched_start')
        matched_length = chain.get('matched_length')
        matched_ids = chain.get('matched_ids')
        draft_ids = chain.get('draft_ids')
        decisions = chain.get('decisions')
        for key, value in [('chain', chain_number), ('context_size', context_size),
                           ('matched_start', matched_start), ('matched_length', matched_length)]:
            expect(integer(value), where+'.'+key, 'must be an integer')
        for key, value in [('matched_ids', matched_ids), ('draft_ids', draft_ids), ('decisions', decisions)]:
            expect(isinstance(value, list), where+'.'+key, 'must be an array')
        if not all(integer(x) for x in (chain_number, context_size, matched_start, matched_length)):
            continue
        if not all(isinstance(x, list) for x in (matched_ids, draft_ids, decisions)):
            continue
        valid_context = prefill <= context_size < len(full)
        expect(valid_context, where+'.context_size', 'must identify an available generated-token position')
        expect(matched_length >= min_ngram, where+'.matched_length', 'match shorter than configured minimum')
        expect(matched_length <= 16, where+'.matched_length', 'match exceeds ngram maximum of 16')
        valid_match = matched_start >= 0 and matched_length > 0 and matched_start + matched_length < context_size
        expect(valid_match, where+'.matched_start', 'match must precede tail and contain a known continuation')
        expect(bool(draft_ids), where+'.draft_ids', 'chain must contain proposals')
        expect(len(decisions) == len(draft_ids), where+'.decisions', 'every proposal requires one decision')
        counts['proposed'] += len(draft_ids)
        if previous_context is not None:
            expect(context_size > previous_context, where+'.context_size', 'chains must advance in context order')
            expect(context_size >= previous_end, where+'.context_size', 'chain overlaps earlier committed tokens')
            expect(chain_number > previous_number, where+'.chain', 'chain IDs must increase')
        previous_context, previous_number = context_size, chain_number
        if not valid_context or not valid_match:
            previous_end = context_size
            continue
        ctx = full[:context_size]
        expect(matched_ids == ctx[matched_start:matched_start+matched_length], where+'.matched_ids',
               'matched source IDs differ from independent baseline context')
        expect(matched_ids == ctx[-matched_length:], where+'.matched_ids',
               'matched source IDs differ from current context suffix')
        expect(matched_start + matched_length + len(draft_ids) <= context_size, where+'.draft_ids',
               'draft copies unavailable future tokens')
        expect(draft_ids == ctx[matched_start+matched_length:matched_start+matched_length+len(draft_ids)],
               where+'.draft_ids', 'draft differs from matched historical continuation')
        expect(chain.get('executor_position_before') == context_size-1, where+'.executor_position_before',
               'executor must be positioned on last committed context token')
        expect(chain.get('executor_last_token_before') == ctx[-1], where+'.executor_last_token_before',
               'executor last token differs from independent baseline context')
        state_context = context_size
        state_position = context_size-1
        broken = False
        discarded_started = False
        for step, decision in enumerate(decisions):
            dw = where+f'.decisions[{step}]'
            if not isinstance(decision, dict):
                errors.append({'location': dw, 'message': 'must be an object'})
                continue
            expected_candidate = context_size + step
            expect(decision.get('draft_position') == expected_candidate, dw+'.draft_position',
                   'candidate must retain its original proposed sequence position')
            expect(step < len(draft_ids) and decision.get('draft_id') == draft_ids[step], dw+'.draft_id',
                   'decision ID differs from proposal')
            expect(decision.get('executor_position_before') == state_position, dw+'.executor_position_before',
                   'executor position must equal preceding decision state')
            expect(decision.get('context_size_before') == state_context, dw+'.context_size_before',
                   'context must equal preceding decision state')
            outcome = decision.get('decision')
            reason = decision.get('reason')
            expect(isinstance(reason, str) and bool(reason.strip()), dw+'.reason', 'a reason is required')
            if outcome in ('accepted', 'rejected'):
                counts['verified'] += 1
                counts[outcome] += 1
                expect(decision.get('verified') is True, dw+'.verified', 'accepted/rejected candidate must be verified')
                expect(not broken and not discarded_started, dw+'.decision', 'cannot verify a broken/discarded chain')
                expect(expected_candidate == state_context, dw+'.draft_position',
                       'verified candidate must be the next committed position')
                offset = expected_candidate-prefill
                in_range = 0 <= offset < len(baseline)
                expect(in_range, dw+'.draft_position', 'verified candidate lies outside baseline stream')
                if in_range:
                    target = baseline[offset]
                    expect(decision.get('target_id') == target, dw+'.target_id',
                           f'target differs from baseline greedy token {target}')
                    candidate_matches = decision.get('draft_id') == target
                    expect(candidate_matches == (outcome == 'accepted'), dw+'.decision',
                           'accept/reject outcome differs from greedy token equality')
                    expect(decision.get('committed_id') == target, dw+'.committed_id',
                           'actual executor last token must be target ID after accepted/rejected commit')
                expect(decision.get('target_logits_position') == expected_candidate-1, dw+'.target_logits_position',
                       'target logits must be from preceding committed token position')
                state_position += 1
                state_context += 1
                if outcome == 'rejected':
                    broken = True
            elif outcome == 'discarded':
                counts['discarded'] += 1
                discarded_started = True
                expect(decision.get('verified') is False, dw+'.verified', 'discarded candidate must remain unverified')
                for key in ('target_id', 'target_logits_position', 'committed_id'):
                    expect(key in decision and decision[key] is None, dw+'.'+key,
                           'discard must have explicit null target/commit fields')
                expect(broken or state_context >= len(full), dw+'.decision',
                       'discard requires chain rejection or exhausted token budget')
            else:
                errors.append({'location': dw+'.decision', 'message': 'unknown outcome'})
            expect(decision.get('executor_position_after') == state_position, dw+'.executor_position_after',
                   'executor must advance once for verification and remain unchanged for discard')
            expect(decision.get('context_size_after') == state_context, dw+'.context_size_after',
                   'context must advance once for verification and remain unchanged for discard')
        previous_end = state_context
    expect(counts['proposed'] == counts['accepted']+counts['rejected']+counts['discarded'], 'accounting',
           'proposals must partition into accepted, rejected and discarded')
    if integer(forward_calls):
        expect(counts['verified'] <= forward_calls, 'accounting', 'verified decisions exceed target decode forwards')
    if not errors:
        warnings.append('Diagnostic trace alignment is valid; this does not certify acceleration, KV contents, or runtime measurement provenance.')
    return {'valid': not errors, 'baseline_tokens': len(baseline), 'prefill_tokens': prefill,
            'target_decode_forward_calls': forward_calls, 'min_ngram': min_ngram,
            'counts': counts, 'errors': errors, 'notes': warnings}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace', required=True, type=Path)
    parser.add_argument('--baseline', required=True, type=Path)
    parser.add_argument('--min-ngram', type=int, default=3,
                        help='Minimum ngram length used by trace; default 3 checks expected first chain position 88')
    args = parser.parse_args()
    try:
        trace = json.loads(read_text(args.trace))
        text = read_text(args.baseline)
        match = re.search(r'TOKSTREAM:\s*([0-9\s]+)', text)
        if not match:
            raise ValueError('baseline log contains no TOKSTREAM')
        baseline = [int(token) for token in match.group(1).split()]
        if len(baseline) != 128:
            raise ValueError(f'expected independent 128-token baseline, found {len(baseline)}')
        result = validate(trace, baseline, args.min_ngram)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        result = {'valid': False, 'errors': [{'location': 'input', 'message': str(exc)}]}
    result['trace'] = str(args.trace.resolve())
    result['baseline'] = str(args.baseline.resolve())
    print(json.dumps(result, indent=2))
    return 0 if result.get('valid') else 1


if __name__ == '__main__':
    sys.exit(main())
