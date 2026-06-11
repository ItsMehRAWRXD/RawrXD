import os
import re

def remove_comments_and_strings(content):
    content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
    content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
    content = re.sub(r'".*?"', '""', content)
    content = re.sub(r"'.*?'", "''", content)
    return content

def find_unclosed_ns(root_dir):
    results = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for fname in filenames:
            if fname.endswith(('.h', '.hpp')):
                fpath = os.path.join(dirpath, fname)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    cleaned = remove_comments_and_strings(content)
                    lines = cleaned.split('\n')
                    
                    brace_depth = 0
                    ns_start_line = 0
                    in_ns = False
                    
                    for i, line in enumerate(lines, 1):
                        stripped = line.strip()
                        
                        if re.search(r'namespace\s+RawrXD\s*\{', stripped):
                            if not in_ns:
                                in_ns = True
                                ns_start_line = i
                            brace_depth += stripped.count('{')
                            brace_depth -= stripped.count('}')
                            if brace_depth <= 0:
                                in_ns = False
                                brace_depth = 0
                            continue
                        
                        if in_ns:
                            brace_depth += stripped.count('{')
                            brace_depth -= stripped.count('}')
                    
                    if in_ns and brace_depth != 0:
                        results.append((fpath, ns_start_line, brace_depth))
                except Exception as e:
                    pass
    
    return results

results = find_unclosed_ns(r'd:\rawrxd\src')
if results:
    print('=== Headers with unclosed namespace RawrXD ===')
    for fpath, line, depth in results:
        print(f'{fpath}:{line} (unclosed depth: {depth})')
else:
    print('No unclosed namespace RawrXD blocks found.')
