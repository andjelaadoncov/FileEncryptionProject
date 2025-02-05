using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptographyWebApp
{
    public class RC6Cipher : ICipher
    {

        private const int W = 32; //velicina reci
        private const int R = 20; //rc6 koristi 20 rundi za sifrovanje 
        private const uint P32 = 0xB7E15163; // Konstantno P za generisanje ključa
        private const uint Q32 = 0x9E3779B9; // Konstantno Q za generisanje ključa
        private uint[] S; // Prošireni ključ

        private static uint RotateLeft(uint value, int shift) => (value << shift) | (value >> (32 - shift));
        private static uint RotateRight(uint value, int shift) => (value >> shift) | (value << (32 - shift));

        private void KeySchedule(byte[] key)
        {
            int c = key.Length / 4;
            uint[] L = new uint[c];
            for (int i = 0; i < c; i++)
            {
                L[i] = BitConverter.ToUInt32(key, i * 4);
            }

            int t = 2 * (R + 2); // Broj podključeva
            S = new uint[t];
            S[0] = P32;
            for (int i = 1; i < t; i++)
            {
                S[i] = S[i - 1] + Q32;
            }

            uint A = 0, B = 0;
            int i1 = 0, j = 0;
            int v = 3 * Math.Max(t, c);
            for (int s = 0; s < v; s++)
            {
                A = S[i1] = RotateLeft(S[i1] + A + B, 3);
                B = L[j] = RotateLeft(L[j] + A + B, (int)(A + B));
                i1 = (i1 + 1) % t;
                j = (j + 1) % c;
            }
        }

        private byte[] ApplyPadding(byte[] input)
        {
            int paddingLength = 16 - (input.Length % 16);
            byte[] paddedInput = new byte[input.Length + paddingLength];
            Array.Copy(input, paddedInput, input.Length);
            for (int i = input.Length; i < paddedInput.Length; i++)
            {
                paddedInput[i] = (byte)paddingLength; // PKCS7 padding
            }
            return paddedInput;
        }

        private byte[] RemovePadding(byte[] input)
        {
            int paddingLength = input[input.Length - 1];
            byte[] unpaddedInput = new byte[input.Length - paddingLength];
            Array.Copy(input, unpaddedInput, unpaddedInput.Length);
            return unpaddedInput;
        }


        public byte[] Encrypt(byte[] input, byte[] key)
        {
            KeySchedule(key);

            byte[] paddedInput = ApplyPadding(input);
            byte[] output = new byte[paddedInput.Length];

            for (int offset = 0; offset < paddedInput.Length; offset += 16)
            {
                uint A = BitConverter.ToUInt32(paddedInput, offset);
                uint B = BitConverter.ToUInt32(paddedInput, offset + 4);
                uint C = BitConverter.ToUInt32(paddedInput, offset + 8);
                uint D = BitConverter.ToUInt32(paddedInput, offset + 12);

                B += S[0];
                D += S[1];
                for (int i = 1; i <= R; i++)
                {
                    uint t = RotateLeft(B * (2 * B + 1), 5);
                    uint u = RotateLeft(D * (2 * D + 1), 5);
                    A = RotateLeft(A ^ t, (int)u) + S[2 * i];
                    C = RotateLeft(C ^ u, (int)t) + S[2 * i + 1];

                    uint temp = A;
                    A = B;
                    B = C;
                    C = D;
                    D = temp;
                }

                A += S[2 * R + 2];
                C += S[2 * R + 3];

                Buffer.BlockCopy(BitConverter.GetBytes(A), 0, output, offset, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(B), 0, output, offset + 4, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(C), 0, output, offset + 8, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(D), 0, output, offset + 12, 4);
            }

            return output;
        }


        public byte[] Decrypt(byte[] input, byte[] key)
        {
            KeySchedule(key);

            byte[] output = new byte[input.Length];

            for (int offset = 0; offset < input.Length; offset += 16)
            {
                uint A = BitConverter.ToUInt32(input, offset);
                uint B = BitConverter.ToUInt32(input, offset + 4);
                uint C = BitConverter.ToUInt32(input, offset + 8);
                uint D = BitConverter.ToUInt32(input, offset + 12);

                C -= S[2 * R + 3];
                A -= S[2 * R + 2];
                for (int i = R; i >= 1; i--)
                {
                    uint temp = D;
                    D = C;
                    C = B;
                    B = A;
                    A = temp;

                    uint u = RotateLeft(D * (2 * D + 1), 5);
                    uint t = RotateLeft(B * (2 * B + 1), 5);
                    C = RotateRight(C - S[2 * i + 1], (int)t) ^ u;
                    A = RotateRight(A - S[2 * i], (int)u) ^ t;
                }

                D -= S[1];
                B -= S[0];

                Buffer.BlockCopy(BitConverter.GetBytes(A), 0, output, offset, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(B), 0, output, offset + 4, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(C), 0, output, offset + 8, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(D), 0, output, offset + 12, 4);
            }

            return RemovePadding(output);
        }

    }

}