import glob

files = glob.glob(r"D:\rawrxd\src\**\*.cpp", recursive=True) + glob.glob(r"D:\rawrxd\src\**\*.hpp", recursive=True) + glob.glob(r"D:\rawrxd\src\**\*.h", recursive=True)
for f in files:
    try:
        with open(f, 'r', encoding='utf-8') as file:
            content = file.read()
            if 'LOAD_WITH_ALTERED_SEARCH_PATH' in content:
                print(f"File: {f}")
    except Exception as e:
        pass
