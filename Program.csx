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
            byte[] iv;
            byte[] encrypted;
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.GenerateIV();
                iv = aesAlg.IV;

                Console.WriteLine($"iv: [{string.Join(", ", iv)}]");
                var encryptor = GetCryptoTransform(aesAlg, true, key, iv);
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(data);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            var combinedIvCt = new byte[iv.Length + encrypted.Length];
            Array.Copy(iv, 0, combinedIvCt, 0, iv.Length);
            Array.Copy(encrypted, 0, combinedIvCt, iv.Length, encrypted.Length);
            return Convert.ToBase64String(combinedIvCt);
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
            string plaintext = null;
            using (Aes aesAlg = Aes.Create())
            {
                byte[] iv = new byte[16];
                byte[] cipherText = new byte[cipherTextCombined.Length - iv.Length];

                Array.Copy(cipherTextCombined, iv, iv.Length);
                Array.Copy(cipherTextCombined, iv.Length, cipherText, 0, cipherText.Length);

                Console.WriteLine($"iv: [{string.Join(", ", iv)}]");
                var decryptor = GetCryptoTransform(aesAlg, false, key, iv);
                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }

        static byte[] ComputeSha256Hash(string rawData)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                return sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));
            }
        }

        static ICryptoTransform GetCryptoTransform(Aes aesAlg, bool encrypt, string key, byte[] iv)
        {
            var keyDigest = ComputeSha256Hash(key);
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.IV = iv;
            aesAlg.Key = keyDigest;
            return encrypt ? aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV) : aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
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