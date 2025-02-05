namespace CryptographyWebApp.Services
{
    public class CryptoService
    {
        public byte[] EncryptFile(byte[] fileData, string algorithm, byte[] key)
        {
            ICipher cipher = algorithm switch
            {
                "Bifid" => new BifidCipher(Convert.ToBase64String(key)),
                "RC6" => new RC6Cipher(),
                "RC6 OFB" => new RC6OFB(),
                _ => throw new ArgumentException("Nepoznat algoritam")
            };

            return cipher.Encrypt(fileData, key);
        }

        public byte[] DecryptFile(byte[] fileData, string algorithm, byte[] key)
        {
            try
            {
                Console.WriteLine($"CryptoService.DecryptFile - Algorithm: {algorithm}");
                Console.WriteLine($"File data length: {fileData?.Length ?? 0}");
                Console.WriteLine($"Key length: {key?.Length ?? 0}");

                if (fileData == null || fileData.Length == 0)
                    throw new ArgumentException("Input file data is empty or null.");
                if (key == null || key.Length == 0)
                    throw new ArgumentException("Decryption key is empty or null.");

                ICipher cipher = algorithm switch
                {
                    "Bifid" => new BifidCipher(Convert.ToBase64String(key)),
                    "RC6" => new RC6Cipher(),
                    "RC6 OFB" => new RC6OFB(),
                    _ => throw new ArgumentException($"Nepoznat algoritam: {algorithm}")
                };

                return cipher.Decrypt(fileData, key);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in CryptoService.DecryptFile: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                if (ex.InnerException != null)
                {
                    Console.WriteLine($"Inner exception: {ex.InnerException.Message}");
                    Console.WriteLine($"Inner stack trace: {ex.InnerException.StackTrace}");
                }
                throw new InvalidOperationException("Decryption failed. Ensure the input data and key are valid.", ex);
            }
        }


    }

}
