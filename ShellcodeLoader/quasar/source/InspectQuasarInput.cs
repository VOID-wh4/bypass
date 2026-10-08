using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

internal static class InspectQuasarInput
{
    private static readonly string[] ExpectedFieldTypes =
    {
        "System.String", "System.String", "System.Int32",
        "System.Environment/SpecialFolder", "System.String", "System.String",
        "System.String", "System.Boolean", "System.Boolean", "System.String",
        "System.String", "System.Boolean", "System.Boolean", "System.String",
        "System.String", "System.String", "System.String", "System.String",
        "System.Security.Cryptography.X509Certificates.X509Certificate2",
        "System.Boolean", "System.Boolean", "System.String", "System.String",
        "System.Boolean"
    };

    private static int Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.Error.WriteLine("Usage: InspectQuasarInput.exe <quasar-client.exe>");
            return 2;
        }

        try
        {
            using (ModuleDefMD module = ModuleDefMD.Load(args[0]))
            {
                TypeDef settings = module.GetTypes().FirstOrDefault(type =>
                    type.Fields.Count == ExpectedFieldTypes.Length &&
                    type.Fields.All(field => field.IsStatic) &&
                    type.Fields.Select(field => field.FieldType.FullName)
                        .SequenceEqual(ExpectedFieldTypes));
                if (settings == null)
                    throw new InvalidDataException("The input is not a supported Quasar client.");

                Dictionary<int, object> values = ReadConstants(settings);
                string masterKey = StringValue(values, 13, "encryption key");
                var aes = new Aes256(masterKey);
                string version = aes.Decrypt(StringValue(values, 0, "version"));
                string hosts = aes.Decrypt(StringValue(values, 1, "hosts"));
                string expectedThumbprint = masterKey;
                string certificateText = aes.Decrypt(
                    StringValue(values, 17, "server certificate"));
                byte[] certificateBytes = Convert.FromBase64String(certificateText);

                using (var certificate = new X509Certificate2(certificateBytes))
                {
                    if (!string.Equals(expectedThumbprint, certificate.Thumbprint,
                        StringComparison.OrdinalIgnoreCase))
                        throw new CryptographicException(
                            "The embedded certificate thumbprint does not match the Quasar settings.");

                    Console.WriteLine("Version={0}", version);
                    Console.WriteLine("Hosts={0}", hosts);
                    Console.WriteLine("CertificateThumbprint={0}", certificate.Thumbprint);
                    Console.WriteLine("CertificateSubject={0}", certificate.Subject);
                }

                Array.Clear(certificateBytes, 0, certificateBytes.Length);
            }
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception.Message);
            return 1;
        }
    }

    private static Dictionary<int, object> ReadConstants(TypeDef settings)
    {
        var result = new Dictionary<int, object>();
        MethodDef constructor = settings.FindStaticConstructor();
        if (constructor == null || !constructor.HasBody)
            throw new InvalidDataException("Quasar settings initializer is missing.");

        IList<Instruction> instructions = constructor.Body.Instructions;
        for (int index = 1; index < instructions.Count; index++)
        {
            if (instructions[index].OpCode != OpCodes.Stsfld)
                continue;
            IField reference = instructions[index].Operand as IField;
            FieldDef field = reference == null ? null : reference.ResolveFieldDef();
            if (field == null || field.DeclaringType != settings)
                continue;
            Instruction previous = instructions[index - 1];
            int fieldIndex = settings.Fields.IndexOf(field);
            if (previous.OpCode == OpCodes.Ldstr)
                result[fieldIndex] = previous.Operand as string;
            else if (previous.IsLdcI4())
                result[fieldIndex] = previous.GetLdcI4Value();
        }
        return result;
    }

    private static string StringValue(Dictionary<int, object> values, int index,
        string description)
    {
        object value;
        if (!values.TryGetValue(index, out value) || !(value is string))
            throw new InvalidDataException("Quasar " + description + " is missing.");
        return (string)value;
    }

    private sealed class Aes256
    {
        private static readonly byte[] Salt =
        {
            0xBF, 0xEB, 0x1E, 0x56, 0xFB, 0xCD, 0x97, 0x3B,
            0xB2, 0x19, 0x02, 0x24, 0x30, 0xA5, 0x78, 0x43,
            0x00, 0x3D, 0x56, 0x44, 0xD2, 0x1E, 0x62, 0xB9,
            0xD4, 0xF1, 0x80, 0xE7, 0xE6, 0xC3, 0x39, 0x41
        };

        private readonly byte[] key;
        private readonly byte[] authenticationKey;

        internal Aes256(string masterKey)
        {
            using (var derive = new Rfc2898DeriveBytes(masterKey, Salt, 50000))
            {
                key = derive.GetBytes(32);
                authenticationKey = derive.GetBytes(64);
            }
        }

        internal string Decrypt(string value)
        {
            byte[] input = Convert.FromBase64String(value);
            using (var hmac = new HMACSHA256(authenticationKey))
            {
                byte[] expected = hmac.ComputeHash(input, 32, input.Length - 32);
                if (!expected.SequenceEqual(input.Take(32)))
                    throw new CryptographicException("Invalid Quasar settings MAC.");
            }

            using (var aes = new AesCryptoServiceProvider())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.IV = input.Skip(32).Take(16).ToArray();
                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                {
                    byte[] clear = decryptor.TransformFinalBlock(
                        input, 48, input.Length - 48);
                    try
                    {
                        return Encoding.UTF8.GetString(clear);
                    }
                    finally
                    {
                        Array.Clear(clear, 0, clear.Length);
                        Array.Clear(input, 0, input.Length);
                    }
                }
            }
        }
    }
}
