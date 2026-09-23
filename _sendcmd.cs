using System;
using System.Runtime.InteropServices;
public class Win32SendCmd {
    [DllImport("user32.dll",SetLastError=true)]
    public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
    [DllImport("user32.dll",SetLastError=true)]
    public static extern int SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
    public static void Main(string[] args){
        int cmd = args.Length>0 ? int.Parse(args[0]) : 3001;
        IntPtr h = FindWindow("RawrXDWin32IDE",null);
        if(h==IntPtr.Zero){Console.WriteLine("HWND_NOT_FOUND");return;}
        int r = SendMessage(h,0x0111,new IntPtr(cmd),IntPtr.Zero);
        Console.WriteLine("SENT_OK result="+r);
    }
}
