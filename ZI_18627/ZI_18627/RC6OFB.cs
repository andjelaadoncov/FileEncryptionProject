using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ZI_18627
{
    public class RC6OFB : ICipher
    {
        private readonly RC6Cipher _rc6Cipher = new RC6Cipher();

        public byte[] Encrypt(byte[] input, byte[] key)
        {
            // Generisanje IV (inicijalnog vektora)
            byte[] iv = GenerateIV();

            // Pridruži IV na početak izlaza
            byte[] ciphertextWithIV = new byte[iv.Length + input.Length];
            Buffer.BlockCopy(iv, 0, ciphertextWithIV, 0, iv.Length);

            // OFB proces šifrovanja
            byte[] encrypted = OFBMode(input, key, iv, true);
            Buffer.BlockCopy(encrypted, 0, ciphertextWithIV, iv.Length, encrypted.Length);

            return ciphertextWithIV;
        }

        public byte[] Decrypt(byte[] input, byte[] key)
        {
            // Ekstrakcija IV sa početka ulaza
            byte[] iv = ExtractIV(input);
            byte[] ciphertext = new byte[input.Length - iv.Length];
            Buffer.BlockCopy(input, iv.Length, ciphertext, 0, ciphertext.Length);

            // OFB proces dešifrovanja
            return OFBMode(ciphertext, key, iv, false);
        }

        private byte[] OFBMode(byte[] input, byte[] key, byte[] iv, bool encrypt)
        {
            // Keystream generacija pomoću RC6
            byte[] keystreamBlock = new byte[iv.Length];
            Buffer.BlockCopy(iv, 0, keystreamBlock, 0, iv.Length);

            byte[] output = new byte[input.Length];
            for (int i = 0; i < input.Length; i += iv.Length)
            {
                // Šifrovanje IV (keystream generacija)
                keystreamBlock = _rc6Cipher.Encrypt(keystreamBlock, key);

                // XOR keystream-a sa podacima (plaintext/ciphertext)
                for (int j = 0; j < iv.Length && (i + j) < input.Length; j++)
                {
                    output[i + j] = (byte)(input[i + j] ^ keystreamBlock[j]);
                }
            }

            return output;
        }

        private byte[] GenerateIV()
        {
            // Generisanje slučajnog IV-a od 16 bajtova (veličina bloka RC6)
            byte[] iv = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv);
            }
            return iv;
        }

        private byte[] ExtractIV(byte[] input)
        {
            // Prvih 16 bajtova su IV
            byte[] iv = new byte[16];
            Buffer.BlockCopy(input, 0, iv, 0, iv.Length);
            return iv;
        }
    }
}
