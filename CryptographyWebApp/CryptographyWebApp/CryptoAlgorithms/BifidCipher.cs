using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptographyWebApp
{
    public class BifidCipher : ICipher
    {
        private readonly char[,] polybiusSquare = new char[5, 5];
        private readonly Dictionary<char, (int, int)> charToCoordinates = new Dictionary<char, (int, int)>();
        private readonly Dictionary<(int, int), char> coordinatesToChar = new Dictionary<(int, int), char>();

        public BifidCipher(string key = "")
        {
            InitializePolybiusSquare(key);
        }

        public byte[] Encrypt(byte[] input, byte[] key)
        {
            string plaintext = Encoding.UTF8.GetString(input);
            string kljuc = Encoding.UTF8.GetString(key);
            Console.WriteLine("Kljuc koji se koristi je: " + Convert.ToBase64String(key));
            string ciphertext = BifidEncrypt(plaintext.ToUpper());
            return Encoding.UTF8.GetBytes(ciphertext);

        }

        public byte[] Decrypt(byte[] input, byte[] key)
        {
            string ciphertext = Encoding.UTF8.GetString(input);
            string kljuc = Encoding.UTF8.GetString(key);
            Console.WriteLine("Kljuc koji se koristi je: " + Convert.ToBase64String(key));
            string plaintext = BifidDecrypt(ciphertext.ToUpper());
            return Encoding.UTF8.GetBytes(plaintext);
        }

        private void InitializePolybiusSquare(string key)
        {
            string alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"; // Bez J
            HashSet<char> usedChars = new HashSet<char>();
            StringBuilder matrixBuilder = new StringBuilder();

            // Ako postoji ključ, prvo ga dodajemo u Polybius matricu
            if (!string.IsNullOrEmpty(key))
            {
                foreach (char c in key.ToUpper())
                {
                    if (alphabet.Contains(c) && !usedChars.Contains(c))
                    {
                        matrixBuilder.Append(c);
                        usedChars.Add(c);
                    }
                }
            }

            // Dodajemo preostala slova
            foreach (char c in alphabet)
            {
                if (!usedChars.Contains(c))
                {
                    matrixBuilder.Append(c);
                }
            }

            // Popunjavamo matricu
            int index = 0;
            for (int row = 0; row < 5; row++)
            {
                for (int col = 0; col < 5; col++)
                {
                    char letter = matrixBuilder[index++];
                    polybiusSquare[row, col] = letter;
                    charToCoordinates[letter] = (row, col);
                    coordinatesToChar[(row, col)] = letter;
                }
            }
        }

        private string BifidEncrypt(string plaintext)
        {
            List<int> rows = new List<int>();
            List<int> cols = new List<int>();
            Dictionary<int, char> specialCharacters = new Dictionary<int, char>();

            // Sačuvaj specijalne znakove i razmake
            for (int i = 0; i < plaintext.Length; i++)
            {
                char c = plaintext[i];
                if (!charToCoordinates.ContainsKey(c))
                {
                    specialCharacters[i] = c;
                }
                else
                {
                    var coordinates = charToCoordinates[c];
                    rows.Add(coordinates.Item1);
                    cols.Add(coordinates.Item2);
                }
            }

            // Mešamo koordinate
            List<int> mixed = new List<int>();
            mixed.AddRange(rows);
            mixed.AddRange(cols);

            // Delimo koordinate u parove i generišemo šifrat
            StringBuilder ciphertext = new StringBuilder();
            int charIndex = 0;
            for (int i = 0; i < plaintext.Length; i++)
            {
                if (specialCharacters.ContainsKey(i))
                {
                    ciphertext.Append(specialCharacters[i]); // Vrati specijalne znakove
                }
                else
                {
                    int row = mixed[charIndex++];
                    int col = mixed[charIndex++];
                    ciphertext.Append(coordinatesToChar[(row, col)]);
                }
            }

            return ciphertext.ToString();
        }


        private string BifidDecrypt(string ciphertext)
        {
            List<int> coordinates = new List<int>();
            Dictionary<int, char> specialCharacters = new Dictionary<int, char>();

            // Sačuvaj specijalne znakove i razmake
            for (int i = 0; i < ciphertext.Length; i++)
            {
                char c = ciphertext[i];
                if (!charToCoordinates.ContainsKey(c))
                {
                    specialCharacters[i] = c;
                }
                else
                {
                    var coordinate = charToCoordinates[c];
                    coordinates.Add(coordinate.Item1);
                    coordinates.Add(coordinate.Item2);
                }
            }

            // Delimo koordinate na dve grupe
            int half = coordinates.Count / 2;
            List<int> rows = coordinates.GetRange(0, half);
            List<int> cols = coordinates.GetRange(half, half);

            // Obnavljamo originalni tekst iz koordinata
            StringBuilder plaintext = new StringBuilder();
            int coordIndex = 0;
            for (int i = 0; i < ciphertext.Length; i++)
            {
                if (specialCharacters.ContainsKey(i))
                {
                    plaintext.Append(specialCharacters[i]); // Vrati specijalne znakove
                }
                else
                {
                    int row = rows[coordIndex];
                    int col = cols[coordIndex];
                    plaintext.Append(coordinatesToChar[(row, col)]);
                    coordIndex++;
                }
            }

            return plaintext.ToString();
        }
    }

}
