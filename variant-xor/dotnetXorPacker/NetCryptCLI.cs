using System;
using System.IO;
using Netcrypt;

namespace NetCryptCLI
{
    static class Program
    {
        static void PrintUsage()
        {
            Console.WriteLine("Usage: NetCryptCLI <input.exe> <output.exe> [dependency.dll ...]");
            Console.WriteLine("Example:");
            Console.WriteLine("  NetCryptCLI Client.exe PackedClient.exe BouncyCastle.Crypto.dll Gma.System.MouseKeyHook.dll Quasar.Common.dll");
        }

        static int Main(string[] args)
        {
            if (args.Length < 2)
            {
                PrintUsage();
                return 1;
            }

            try
            {
                byte[] mainAssembly = File.ReadAllBytes(args[0]);

                int depCount = args.Length - 2;
                string[] depNames = new string[depCount];
                byte[][] depBytes = new byte[depCount][];

                for (int i = 0; i < depCount; i++)
                {
                    depNames[i] = Path.GetFileNameWithoutExtension(args[i + 2]);
                    depBytes[i] = File.ReadAllBytes(args[i + 2]);
                    Console.WriteLine("Embedding dependency: " + depNames[i] + " (" + depBytes[i].Length + " bytes)");
                }

                byte[] packed = Packer.Pack(mainAssembly, depNames, depBytes, DotNetVersion.v4_0);
                if (packed == null)
                {
                    Console.Error.WriteLine("Packing failed (null output).");
                    return 2;
                }

                File.WriteAllBytes(args[1], packed);
                Console.WriteLine("Packed: " + args[1] + " (" + packed.Length + " bytes)");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.ToString());
                return 3;
            }
        }
    }
}
