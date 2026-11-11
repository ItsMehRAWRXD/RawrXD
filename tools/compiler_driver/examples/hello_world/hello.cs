// Hello World in C# for RAWRXD Compiler Driver
// Compile with: rawrxd-compiler compile hello.cs

using System;

namespace HelloWorld
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello, World from RAWRXD C# Compiler!");
            Console.WriteLine("This file was compiled using the unified compiler driver.");
            
            if (args.Length > 0)
            {
                Console.WriteLine($"Arguments: {string.Join(", ", args)}");
            }
        }
    }
}
