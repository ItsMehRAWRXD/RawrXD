// EditorCLI.cs
using System;
using System.Threading.Tasks;

public static class EditorCLI
{
    public static void Main()
    {
        var ide = new EnhancedCursorIDE();

        Console.WriteLine("Enhanced Cursor IDE - Continue.dev Hub Integration");
        Console.WriteLine("Commands: /key <provider> <key>, /switch <provider>, /complete <code>, /providers, /quit");

        while (true)
        {
            Console.Write("[" + ide.ActiveProvider + "] > ");
            var input = Console.ReadLine();
            if (input == null) break;

            if (input == "/quit") break;

            if (input.StartsWith("/key ", StringComparison.Ordinal))
            {
                var parts = input.Substring(5).Split(new[] { ' ' }, 2);
                if (parts.Length == 2)
                {
                    ide.SetApiKey(parts[0], parts[1]);
                    Console.WriteLine("OK API key set for " + parts[0]);
                }
            }
            else if (input.StartsWith("/switch ", StringComparison.Ordinal))
            {
                var provider = input.Substring(8);
                if (ide.HasApiKey(provider))
                {
                    ide.SwitchProvider(provider);
                    Console.WriteLine("OK Switched to " + provider);
                }
                else
                {
                    Console.WriteLine("X No API key for " + provider);
                }
            }
            else if (input.StartsWith("/complete ", StringComparison.Ordinal))
            {
                var code = input.Substring(10);
                ide.Complete(code).ContinueWith(
                    t => Console.WriteLine("AI: " + t.Result),
                    TaskScheduler.Default);
            }
            else if (input == "/providers")
            {
                Console.WriteLine("Available: " + string.Join(", ", ide.GetProviders()));
                foreach (var provider in ide.GetProviders())
                    Console.WriteLine("  " + (ide.HasApiKey(provider) ? "OK" : "X") + " " + provider);
            }
        }

        ide.Shutdown();
        Console.WriteLine("Goodbye!");
    }
}
