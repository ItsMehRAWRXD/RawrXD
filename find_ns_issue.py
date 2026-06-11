import os
import re

def remove_comments_and_strings(line):
    result = re.sub(r'".*?"', '""', line)
    result = re.sub(r"'.*?'", "''", result)
    result = re.sub(r'//.*$', '', result)
    return result

def find_includes_in_namespace(root_dir):
    results = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for fname in filenames:
            if fname.endswith(('.h', '.hpp', '.c', '.cpp')):
                fpath = os.path.join(dirpath, fname)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.read().split('\n')
                    
                    in_rawrxd = False
                    brace_depth = 0
                    ns_start_line = 0
                    
                    for i, line in enumerate(lines, 1):
                        cleaned = remove_comments_and_strings(line).strip()
                        
                        ns_match = re.search(r'namespace\s+RawrXD\s*\{', cleaned)
                        if ns_match:
                            if not in_rawrxd:
                                in_rawrxd = True
                                ns_start_line = i
                                brace_depth = cleaned.count('{')
                            else:
                                brace_depth += cleaned.count('{')
                            brace_depth -= cleaned.count('}')
                            if brace_depth <= 0:
                                in_rawrxd = False
                            continue
                        
                        if in_rawrxd:
                            brace_depth += cleaned.count('{')
                            brace_depth -= cleaned.count('}')
                            
                            if cleaned.startswith('#include'):
                                results.append((fpath, i, line.strip(), ns_start_line))
                            
                            if re.search(r'namespace\s+std\s*\{', cleaned):
                                results.append((fpath, i, 'NESTED_STD: ' + line.strip(), ns_start_line))
                            
                            if brace_depth <= 0:
                                in_rawrxd = False
                except Exception as e:
                    pass
    
    return results

results = find_includes_in_namespace(r'd:\rawrxd\src')
if results:
    print('=== CRITICAL: Found inside namespace RawrXD ===')
    for fpath, line, content, start_line in results:
        print(f'{fpath}:{line} (ns opened at {start_line}): {content}')
else:
    print('No includes or nested std found inside namespace RawrXD.')
