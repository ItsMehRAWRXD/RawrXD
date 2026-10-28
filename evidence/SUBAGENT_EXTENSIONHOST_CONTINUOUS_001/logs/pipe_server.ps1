Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.IO.Pipes;
using System.Threading;
public class ExtHostPipeSrv {
  public static int Run(string pipeName, int waitMs) {
    using (var server = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous)) {
      var ar = server.BeginWaitForConnection(null, null);
      if (!ar.AsyncWaitHandle.WaitOne(waitMs)) return 2;
      server.EndWaitForConnection(ar);
      byte[] buf = new byte[65536];
      int total = 0;
      server.ReadTimeout = 5000;
      try {
        while (true) {
          int n = server.Read(buf, total, buf.Length - total);
          if (n <= 0) break;
          total += n;
          if (total >= 8) break; // got length prefix + some payload
        }
      } catch { }
      File.WriteAllText(@"G:\\~dev\\rawrxd\\evidence\\SUBAGENT_EXTENSIONHOST_CONTINUOUS_001\\logs\pipe_server_bytes.txt", "BYTES=" + total);
      return total > 0 ? 0 : 3;
    }
  }
}
"@
$rc = [ExtHostPipeSrv]::Run("RawrXD_ExtensionHost", 20000)
exit $rc
