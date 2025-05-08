using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;

namespace SignatureVerification
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string publicKeyHex = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100c54bb7c2e93244be1232dd2e57a4f8b78e070e4aa4e10c42007f2451afeb5b82bf8d8aea94abd47a0ff73429e5bbb980061bfa4ff51053d5322b1459eeaa73a9d7d79a1758bf10a290faa32bcb9d56af39bbd6f5297eb2ebf8924c9fd25afb690b12942f1faf73c1e2db2f720777f3ce801cd2efdaacf42fd56d36ba35390c082638585161fda7c3ab2cd8188edf5450900364e5ef6df765b46f6104704a9ce0222a3acb4edd1110f74d4f030fc6c906d13abc332d1fc873328b577c1af138cb8f24f79823d7fa321e2b8cf6025a98da3c129bc25d39fb14e4d4a5eadb909bc0713f86d29ed7c418a755efca2f9664cab3df3c8a2a70472df679de0542c8d7490203010001"; // <-- PUT your full public key hex string here
            string signatureHex = "3ec342d1dc5273b414ec34d70cb40571091b4abe71cf8690987f7155ed2bf419555ac7cb8fcdf13636b7e5990f572341e659a750af2ff3ab677f8a6229aca183061e72faef31eaf2040c2c02595dd705a893f3ea8fd01127f0e5556894eff326d2ef7ae34cd4aa67425b6ed22a6e3a4c9dbd6e2aa71c44270ec45a7e5a005f4c464723cb5034836f58e1d830186474023c1afe83bc2d37820b9cef562a7e4becd4d8da8c30f1a472d5f9b60682001e0d524aef6019ef931a914a44a55ee4304740e18a8f4f85bd731d2c3c14e00687dbe3aed4b77f0516ece3afb1664188fb8d5cde15bbc68b5d90f8eee626cb8ba52f4a29d03ee494f454cad153237cefe386"; // <-- PUT your full signature hex string here
            string digestHex = "ab2824da3f963967bbf3e3d548617e267a304cef2785e5b4ab10c6410fec8c18";    // <-- Example digest (hex string)
            string timestamp = "2025-04-03T07:01:57.020831+00:00"; // <-- Example timestamp


            bool isValid = SignatureVerifier.VerifySignature(publicKeyHex, signatureHex, digestHex, timestamp);

            Console.WriteLine(isValid ? "Signature is valid." : "Signature is INVALID.");
        }
    }

    public class SignatureVerifier
    {
        // Converts hex string to byte[]
        public static byte[] HexStringToByteArray(string hex)
        {
            if (hex.Length % 2 != 0)
                throw new ArgumentException("Hex string must have an even length");

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);

            return bytes;
        }

        public static bool VerifySignature(string publicKeyHex, string signatureHex, string digestHex, string timestamp)
        {
            // Step 1: Convert hex DER public key to byte[]
            byte[] publicKeyBytes = HexStringToByteArray(publicKeyHex);

            // Step 2: Parse public key using BouncyCastle
            AsymmetricKeyParameter keyParam = PublicKeyFactory.CreateKey(publicKeyBytes);
            RsaKeyParameters rsaParams = (RsaKeyParameters)keyParam;

            // Step 3: Convert to .NET RSAParameters
            RSAParameters rsaDotNetParams = new RSAParameters
            {
                Modulus = rsaParams.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaParams.Exponent.ToByteArrayUnsigned()
            };

            // Step 4: Create combined data
            string combined = digestHex + timestamp;
            byte[] combinedBytes = Encoding.UTF8.GetBytes(combined);

            // Step 5: Convert hex signature to byte[]
            byte[] signatureBytes = HexStringToByteArray(signatureHex);

            // Step 6: Verify using RSACryptoServiceProvider
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaDotNetParams);

                // Create the hash of the data
                using (SHA256 sha256 = SHA256.Create())
                {
                    byte[] hash = sha256.ComputeHash(combinedBytes);

                    // Verify the signature
                    return rsa.VerifyHash(hash, CryptoConfig.MapNameToOID("SHA256"), signatureBytes);
                }
            }
        }
    }
}
