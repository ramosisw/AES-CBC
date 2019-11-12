using System.Security.Cryptography;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using System.Text;
using System.IO;
using System;

public class Program
{
    public static class AESCBC
    {

        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <returns>base64EncryptedIVData</returns>
        public static string Encrypt(string data, string key)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.GenerateIV();

                Console.WriteLine($"iv: [{string.Join(", ", aesAlg.IV)}]");
                var encrypted = Transform(aesAlg, true, key, aesAlg.IV, Encoding.UTF8.GetBytes(data));
                var combinedIvCt = new byte[aesAlg.IV.Length + encrypted.Length];
                Array.Copy(aesAlg.IV, 0, combinedIvCt, 0, aesAlg.IV.Length);
                Array.Copy(encrypted, 0, combinedIvCt, aesAlg.IV.Length, encrypted.Length);
                return Convert.ToBase64String(combinedIvCt);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="base64EncryptedIVData"></param>
        /// <param name="key"></param>
        /// <returns>decrypted data</returns>
        public static string Decrypt(string base64EncryptedIVData, string key)
        {
            byte[] cipherTextCombined = Convert.FromBase64String(base64EncryptedIVData);
            using (Aes aesAlg = Aes.Create())
            {
                byte[] iv = new byte[16];
                byte[] cipherText = new byte[cipherTextCombined.Length - iv.Length];

                Array.Copy(cipherTextCombined, iv, iv.Length);
                Array.Copy(cipherTextCombined, iv.Length, cipherText, 0, cipherText.Length);

                Console.WriteLine($"iv: [{string.Join(", ", iv)}]");
                return Encoding.UTF8.GetString(Transform(aesAlg, false, key, iv, cipherText));
            }
        }

        static byte[] ComputeSha256Hash(string rawData)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                return sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));
            }
        }

        static byte[] Transform(Aes aesAlg, bool encrypt, string key, byte[] iv, byte[] bytes)
        {
            var keyDigest = ComputeSha256Hash(key);
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.IV = iv;
            aesAlg.Key = keyDigest;
            var cryptoTransform = encrypt ? aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV) : aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
                    cryptoStream.Write(bytes, 0, bytes.Length);
                return memoryStream.ToArray();
            }
        }

    }

    /// <summary>
    /// Main rutine
    /// </summary>
    public static void Main()
    {
        // PrivateKey shared over languages (KEEP always server side)
        var key = "J1M6sncXwq1NEWLRbqpp4SixZ6fphrcO";

        // Console.WriteLine(AESCBC.Encrypt("Message", key));
        Console.WriteLine("Java");
        Console.WriteLine(AESCBC.Decrypt("88/qWM1tDOsU7BhYWxXQH/jTt9fD17ryDSFuGk6YlPY=", key));
        Console.WriteLine("----");
        Console.WriteLine("C#");
        Console.WriteLine(AESCBC.Decrypt("vDvzP32YQbNhSNphM7uas95lMVR0vUs2vJCfEQaDzMo=", key));
        Console.WriteLine("----");
        Console.WriteLine("NodeJs");
        Console.WriteLine(AESCBC.Decrypt("+nDpo7CTEfsc7I3eOctVNKM57Ai++DzzOlwohKaMU8c=", key));
    }
}

// To run with scriptcs
Program.Main();