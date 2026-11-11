using System;
using System.Runtime.InteropServices;

class P {
  [DllImport("dbghelp.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool SymInitialize(IntPtr hProcess, string UserSearchPath, bool fInvadeProcess);
  [DllImport("dbghelp.dll", SetLastError=true)]
  static extern bool SymCleanup(IntPtr hProcess);
  [DllImport("dbghelp.dll", SetLastError=true)]
  static extern uint SymSetOptions(uint SymOptions);
  [DllImport("dbghelp.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern ulong SymLoadModuleExW(IntPtr hProcess, IntPtr hFile, string ImageName,
      string ModuleName, ulong BaseOfDll, uint DllSize, IntPtr Data, uint Flags);

  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  struct SYMBOL_INFO {
    public uint SizeOfStruct;
    public uint TypeIndex;
    public ulong Reserved0;
    public ulong Reserved1;
    public uint Index;
    public uint Size;
    public ulong ModBase;
    public uint Flags;
    public ulong Value;
    public ulong Address;
    public uint Register;
    public uint Scope;
    public uint Tag;
    public uint NameLen;
    public uint MaxNameLen;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst=1024)]
    public string Name;
  }

  [DllImport("dbghelp.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool SymFromAddrW(IntPtr hProcess, ulong Address, out ulong Displacement,
      ref SYMBOL_INFO Symbol);

  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  struct IMAGEHLP_LINE64 {
    public uint SizeOfStruct;
    public IntPtr Key;
    public uint LineNumber;
    public string FileName;
    public ulong Address;
  }

  [DllImport("dbghelp.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool SymGetLineFromAddrW64(IntPtr hProcess, ulong Address, out uint Displacement,
      ref IMAGEHLP_LINE64 Line);

  static int Main(string[] args) {
    string exe = args[0];
    string search = System.IO.Path.GetDirectoryName(exe);
    IntPtr h = new IntPtr(0x1234);
    SymSetOptions(0x2 | 0x4 | 0x10);
    if (!SymInitialize(h, search, false)) {
      Console.WriteLine("init fail " + Marshal.GetLastWin32Error());
      return 1;
    }
    ulong baseAddr = 0x00007FF604960000UL;
    ulong mod = SymLoadModuleExW(h, IntPtr.Zero, exe, null, baseAddr, 0, IntPtr.Zero, 0);
    Console.WriteLine("mod=" + mod);
    ulong[] offs = { 0xBCFAFUL, 0x876FUL, 0x147010UL, 0x18EAC0UL, 0xBCF00UL, 0xBD100UL };
    foreach (ulong o in offs) {
      SYMBOL_INFO sym = new SYMBOL_INFO();
      sym.MaxNameLen = 1024;
      sym.SizeOfStruct = 88;
      ulong disp;
      bool ok = SymFromAddrW(h, baseAddr + o, out disp, ref sym);
      IMAGEHLP_LINE64 line = new IMAGEHLP_LINE64();
      line.SizeOfStruct = (uint)Marshal.SizeOf(typeof(IMAGEHLP_LINE64));
      uint ldisp;
      bool okL = SymGetLineFromAddrW64(h, baseAddr + o, out ldisp, ref line);
      Console.WriteLine(string.Format(
          "+0x{0:X} ok={1} {2}+0x{3:X} line={4}:{5}",
          o, ok, sym.Name, disp, okL ? line.FileName : "", okL ? line.LineNumber : 0));
    }
    SymCleanup(h);
    return 0;
  }
}
