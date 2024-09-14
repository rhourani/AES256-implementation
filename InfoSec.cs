using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Timers;
namespace AES256ED;

public static class InfoSec
{
    public static string GenerateKey()
    {
        string keyBase64 = "";
        using (Aes aes = Aes.Create())
        {
            aes.KeySize = 256;
            aes.GenerateKey();

            keyBase64 = Convert.ToBase64String(aes.Key);
        }
        return keyBase64;
    }

    public static (string cipher, int time) Encrypt(string PLainText, string Key, out string IVKey)
    {
        var stopWatch = new Stopwatch();
        stopWatch.Start();
        using (Aes aes = Aes.Create())
        {
            aes.Padding = PaddingMode.Zeros;
            aes.Key = Convert.FromBase64String(Key);
            aes.GenerateIV();

            IVKey = Convert.ToBase64String(aes.IV);

            ICryptoTransform encryptor = aes.CreateEncryptor();

            byte[] encryptedDate;

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(PLainText);

                    }
                    encryptedDate = ms.ToArray();
                }
            }
            var timeElapsed = stopWatch.Elapsed.Microseconds;
            return (Convert.ToBase64String(encryptedDate), timeElapsed);
        }
    }

    public static (string plainText, int time) Decrypt(string CipherText, string Key, string IVKey)
    {
        var stopWatch = new Stopwatch();
        stopWatch.Start();
        using (Aes aes = Aes.Create())
        {
            aes.Padding = PaddingMode.Zeros;
            aes.Key = Convert.FromBase64String(Key);
            aes.IV = Convert.FromBase64String(IVKey);

            ICryptoTransform decryptor = aes.CreateDecryptor();

            string PlainText = "";
            byte[] cipher = Convert.FromBase64String(CipherText);

            using (MemoryStream ms = new MemoryStream(cipher))
            {
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader sr = new StreamReader(cs))
                    {
                        PlainText = sr.ReadToEnd();
                    }
                }
            }
            var timeElapsed = stopWatch.Elapsed.Microseconds;
            return (PlainText.ToString().TrimEnd(new char[] { '\0' }), timeElapsed);
        }
    }
}
