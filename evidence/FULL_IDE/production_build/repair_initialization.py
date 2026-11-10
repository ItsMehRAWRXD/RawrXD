from pathlib import Path
import re
p=Path(r'F:\rawrxd\src\win32app\Win32IDE.h')
b=p.read_bytes();s=b.decode('utf-16') if b.startswith(b'\xff\xfe') else b.decode('utf-8-sig')
s=re.sub(r'(^\s*(?:HWND|HANDLE|HMENU|HFONT|HBRUSH|HIMAGELIST|HINSTANCE)\s+m_\w+)\s*;',r'\1 = nullptr;',s,flags=re.M)
s=re.sub(r'(^\s*[\w:]+\*\s+m_\w+)\s*;',r'\1 = nullptr;',s,flags=re.M)
s=s.replace('bool m_inferenceRunning;','bool m_inferenceRunning = false;').replace('bool m_inferenceStopRequested;','bool m_inferenceStopRequested = false;')
p.write_text(s,encoding='utf-8')
