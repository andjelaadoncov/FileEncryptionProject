using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptographyWebApp
{
    public class RC6OFB : ICipher
    {
        private readonly RC6Cipher _rc6Cipher = new RC6Cipher();

        public byte[] Encrypt(byte[] input, byte[] key)
        {
            byte[] iv = GenerateIV();

            using (MemoryStream ms = new MemoryStream())
            {
                ms.Write(iv, 0, iv.Length);

                byte[] encrypted = OFBMode(input, key, iv);
                ms.Write(encrypted, 0, encrypted.Length);

                return ms.ToArray();
            }
        }

        public byte[] Decrypt(byte[] input, byte[] key)
        {
            byte[] iv = new byte[16];
            Buffer.BlockCopy(input, 0, iv, 0, iv.Length);

            byte[] ciphertext = new byte[input.Length - iv.Length];
            Buffer.BlockCopy(input, iv.Length, ciphertext, 0, ciphertext.Length);

            byte[] decrypted = OFBMode(ciphertext, key, iv);

            return decrypted;
        }


        private byte[] OFBMode(byte[] input, byte[] key, byte[] iv)
        {
            int blockSize = 16; // Veličina bloka je 16 bajtova za RC6
            byte[] output = new byte[input.Length];

            byte[] keystreamBlock = new byte[blockSize];
            Buffer.BlockCopy(iv, 0, keystreamBlock, 0, blockSize);

            for (int i = 0; i < (input.Length + blockSize - 1) / blockSize; i++)
            {
                int offset = i * blockSize;

                // Generiši keystream blok
                byte[] localKeystream = _rc6Cipher.Encrypt(keystreamBlock, key);
                Array.Resize(ref localKeystream, blockSize); // Osiguraj da ima tačno 16 bajtova
                Buffer.BlockCopy(localKeystream, 0, keystreamBlock, 0, blockSize);

                // XOR keystream-a sa podacima
                for (int j = 0; j < blockSize && offset + j < input.Length; j++)
                {
                    output[offset + j] = (byte)(input[offset + j] ^ localKeystream[j]);
                }
            }

            return output;
        }



        private byte[] GenerateIV()
        {
            byte[] iv = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv);
            }
            return iv;
        }
    }
}