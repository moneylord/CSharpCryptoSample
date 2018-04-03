using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace CryptoSample
{
    /// <summary>
    /// MainWindow.xaml에 대한 상호 작용 논리
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void Rijndael_Click(object sender, RoutedEventArgs e)
        {
            var tempText = RijndaelTextBlock.Text;

            // key is current MAC address
            var encryptedText = MyRijndael.Encrypt(tempText, NetworkInterface.GetAllNetworkInterfaces()[0].GetPhysicalAddress().ToString());

            RijndaelEncryptTextBlock.Text = encryptedText;            
        }

        private void Rijndael_Decrypt_Click(object sender, RoutedEventArgs e)
        {
            var tempText = RijndaelEncryptTextBlock.Text;

            var decryptedText = MyRijndael.Decrypt(tempText, NetworkInterface.GetAllNetworkInterfaces()[0].GetPhysicalAddress().ToString());

            RijndaelDecryptTextBlock.Text = decryptedText;
        }

        private void Salting_Click(object sender, RoutedEventArgs e)
        {
            var tempText = SaltingTextBlock.Text;

            var resultSalt = MySalting.SaltingText(tempText);

            SaltingResultTextBlock.Text = resultSalt;
        }

        
    }

    public static class MySalting
    {
        public static string SaltingText(string plainText)
        {
            byte[] salt = new byte[32];
            RNGCryptoServiceProvider.Create().GetBytes(salt);

            var testSalt = Encoding.Default.GetString(salt);

            // Convert the plain string pwd into bytes
            byte[] plainTextBytes = UnicodeEncoding.Unicode.GetBytes(plainText);
            // Append salt to pwd before hashing
            byte[] combinedBytes = new byte[plainTextBytes.Length + salt.Length];
            Buffer.BlockCopy(plainTextBytes, 0, combinedBytes, 0, plainTextBytes.Length);
            Buffer.BlockCopy(salt, 0, combinedBytes, plainTextBytes.Length, salt.Length);

            // Create hash for the pwd+salt
            HashAlgorithm hashAlgo = new SHA256Managed();
            byte[] hash = hashAlgo.ComputeHash(combinedBytes);

            // Append the salt to the hash
            byte[] hashPlusSalt = new byte[hash.Length + salt.Length];
            Buffer.BlockCopy(hash, 0, hashPlusSalt, 0, hash.Length);
            Buffer.BlockCopy(salt, 0, hashPlusSalt, hash.Length, salt.Length);

            return Encoding.Default.GetString(hashPlusSalt);
        }

        public static bool ConfirmPassword(string password)
        {
            // Get Byte Array Somewhere...
            byte[] salt = new byte[0];
            byte[] savedHash = new byte[0];
            // Get Byte Array Somewhere...

            byte[] plainTextBytes = UnicodeEncoding.Unicode.GetBytes(password);

            byte[] combinedBytes = new byte[plainTextBytes.Length + salt.Length];
            Buffer.BlockCopy(plainTextBytes, 0, combinedBytes, 0, plainTextBytes.Length);
            Buffer.BlockCopy(salt, 0, combinedBytes, plainTextBytes.Length, salt.Length);

            HashAlgorithm hashAlgo = new SHA256Managed();
            byte[] hash = hashAlgo.ComputeHash(combinedBytes);

            // Compare hash with savedHash
            if (hash.SequenceEqual(savedHash))
                return true;
            else
                return false;
        }
    }

    public static class MyRijndael
    {
        public static string Encrypt(string textToEncrypt, string key)
        {
            RijndaelManaged rijndaelCipher = new RijndaelManaged();
            rijndaelCipher.Mode = CipherMode.CBC;
            rijndaelCipher.Padding = PaddingMode.PKCS7;

            rijndaelCipher.KeySize = 128;
            rijndaelCipher.BlockSize = 128;

            byte[] pwdBytes = Encoding.UTF8.GetBytes(key);
            byte[] keyBytes = new byte[16];
            int len = pwdBytes.Length;
            if (len > keyBytes.Length)
                len = keyBytes.Length;

            Array.Copy(pwdBytes, keyBytes, len);

            rijndaelCipher.Key = keyBytes;
            rijndaelCipher.IV = keyBytes;

            ICryptoTransform transform = rijndaelCipher.CreateEncryptor();
            byte[] plainText = Encoding.UTF8.GetBytes(textToEncrypt);
            return Convert.ToBase64String(transform.TransformFinalBlock(plainText, 0, plainText.Length));
        }

        public static string Decrypt(string textToDecrypt, string key)
        {
            RijndaelManaged rijndaelCipher = new RijndaelManaged();
            rijndaelCipher.Mode = CipherMode.CBC;
            rijndaelCipher.Padding = PaddingMode.PKCS7;

            rijndaelCipher.KeySize = 128;
            rijndaelCipher.BlockSize = 128;

            byte[] encryptedData = Convert.FromBase64String(textToDecrypt);
            byte[] pwdBytes = Encoding.UTF8.GetBytes(key);
            byte[] keyBytes = new byte[16];
            int len = pwdBytes.Length;

            if (len > keyBytes.Length)
                len = keyBytes.Length;

            Array.Copy(pwdBytes, keyBytes, len);
            rijndaelCipher.Key = keyBytes;
            rijndaelCipher.IV = keyBytes;
            byte[] plainText = rijndaelCipher.CreateDecryptor().TransformFinalBlock(encryptedData, 0, encryptedData.Length);

            return Encoding.UTF8.GetString(plainText);
        }
    }
}
