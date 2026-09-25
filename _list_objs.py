import glob, os

# Collect all .obj files from InferenceEngine build directory
obj_dir = r'F:\~dev\rawrxd\build\InferenceEngine.dir\Release'
out_file = r'F:\~dev\_obj_list.txt'

obj_files = []
for f in sorted(glob.glob(os.path.join(obj_dir, '*.obj'))):
    # Exclude old Deep2Engine.obj, include new Deep2Engine_new.obj if present
    if os.path.basename(f).lower() == 'deep2engine.obj':
        continue
    obj_files.append(f)

# Also include the new Deep2Engine_new.obj from build root
new_obj = r'F:\~dev\rawrxd\build\Deep2Engine_new.obj'
if os.path.exists(new_obj):
    obj_files.append(new_obj)

with open(out_file, 'w', encoding='ascii') as fh:
    for o in obj_files:
        fh.write(o + '\n')

print(f"Wrote {len(obj_files)} object files to {out_file}")
