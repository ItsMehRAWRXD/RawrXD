from pathlib import Path
for name in ['Win32IDE.h','Win32IDE.cpp','Win32IDE_Commands.cpp','Win32IDE_lifecycle.cpp']:
 p=Path(r'F:\rawrxd\src\win32app')/name
 b=p.read_bytes()
 print(name,'CRCRLF',b.count(b'\r\r\n'),'CRLF',b.count(b'\r\n'),'LF',b.count(b'\n'))
 if b'\r\r\n' in b: p.write_bytes(b.replace(b'\r\r\n',b'\r\n'))
