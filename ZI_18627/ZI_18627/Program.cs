using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ZI_18627
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string filePath = "C:\\FAKULTET\\7_SEMESTAR\\ZASTITA INFORMACIJA\\projekat_18627\\ZI_18627\\file18627.txt";

            if (!File.Exists(filePath))
            {
                Console.WriteLine("Greška: Navedena putanja nije validna ili fajl ne postoji.");
                return;
            }

            string fileContent = File.ReadAllText(filePath);
            byte[] fileData = Encoding.UTF8.GetBytes(fileContent);

            // Izbor algoritma
            Console.WriteLine("Izaberite algoritam: 1. Bifid, 2. RC6, 3. RC6 OFB");
            int choice;
            while (!int.TryParse(Console.ReadLine(), out choice) || choice < 1 || choice > 3)
            {
                Console.WriteLine("Neispravan unos. Molimo unesite broj: 1, 2 ili 3.");
            }

            // Generisanje ključa korišćenjem Difi-Helman šeme
            using (ECDiffieHellmanCng diffieHellman = new ECDiffieHellmanCng())
            {
                diffieHellman.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                diffieHellman.HashAlgorithm = CngAlgorithm.Sha256;

                byte[] publicKey = diffieHellman.PublicKey.ToByteArray();
                Console.WriteLine("Javni ključ (šalje se primaocu):\n" + Convert.ToBase64String(publicKey));

                // Simulacija deljenja javnog ključa
                Console.WriteLine("Unesite javni ključ primaoca:");
                string recipientPublicKeyBase64 = Console.ReadLine();
                byte[] recipientPublicKey = Convert.FromBase64String(recipientPublicKeyBase64);

                // Generisanje zajedničkog tajnog ključa
                using (ECDiffieHellmanCng recipientKey = new ECDiffieHellmanCng(CngKey.Import(recipientPublicKey, CngKeyBlobFormat.EccPublicBlob)))
                {
                    byte[] sharedKey = diffieHellman.DeriveKeyMaterial(recipientKey.PublicKey);
                    Console.WriteLine("Zajednički ključ generisan: \n" + Convert.ToBase64String(sharedKey));

                    // Izbor algoritma i šifrovanje
                    ICipher cipher;
                    switch (choice)
                    {
                        case 1:
                            cipher = new BifidCipher(Convert.ToBase64String(sharedKey));
                            break;
                        case 2:
                            cipher = new RC6Cipher();
                            break;
                        case 3:
                            cipher = new RC6OFB();
                            break;
                        default:
                            Console.WriteLine("Nepoznat izbor algoritma.");
                            return;
                    }

                    // Šifrovanje
                    byte[] encrypted = cipher.Encrypt(fileData, sharedKey);
                    File.WriteAllBytes("encrypted.dat", encrypted);
                    Console.WriteLine("Fajl je uspešno kodiran i sačuvan u 'encrypted.dat'.");

                    // Dešifrovanje
                    byte[] decrypted = cipher.Decrypt(encrypted, sharedKey);
                    string decryptedContent = Encoding.UTF8.GetString(decrypted);
                    File.WriteAllText("decrypted.txt", decryptedContent);
                    Console.WriteLine("Dešifrovani sadržaj je sačuvan u 'decrypted.txt'.");
                }
            }
        }
    }
}
