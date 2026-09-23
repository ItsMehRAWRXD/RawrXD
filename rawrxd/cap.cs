using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Threading;

class S {
    static void Main() {
        Thread.Sleep(500);
        var bmp = new Bitmap(1920, 1080);
        using (var g = Graphics.FromImage(bmp))
            g.CopyFromScreen(0, 0, 0, 0, new Size(1920, 1080));
        bmp.Save(@"f:\~dev\rawrxd\instagib_003_v4.png", ImageFormat.Png);
        Console.WriteLine("saved");
    }
}
