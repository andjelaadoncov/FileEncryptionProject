using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace CryptographyWebApp.Services
{
    public class FileExchangeService
    {
        private const int Port = 12345;
        private string _selectedAlgorithm;
        private readonly CryptoService _cryptoService;
        private string _sharedKey;

        public async Task StartServer(string selectedAlgorithm, string sharedKey)
        {
            _selectedAlgorithm = selectedAlgorithm;
            _sharedKey = sharedKey;

            TcpListener listener = new TcpListener(IPAddress.Any, Port);
            listener.Start();
            Console.WriteLine("Server started...");

            while (true)
            {
                TcpClient client = await listener.AcceptTcpClientAsync();
                _ = HandleClientAsync(client);
            }
        }

        private async Task HandleClientAsync(TcpClient client)
        {
            try
            {
                using (NetworkStream stream = client.GetStream())
                using (BinaryReader reader = new BinaryReader(stream))
                {
                    string fileName = reader.ReadString();
                    long fileSize = reader.ReadInt64();
                    int hashLength = reader.ReadInt32();
                    byte[] hash = reader.ReadBytes(hashLength);
                    byte[] fileContent = reader.ReadBytes((int)fileSize);

                    // Verify hash
                    byte[] computedHash = ComputeSHA1Hash(fileContent);
                    if (Convert.ToBase64String(computedHash) == Convert.ToBase64String(hash))
                    {
                        // Decrypt file content
                        byte[] decryptedContent = _cryptoService.DecryptFile(fileContent, _selectedAlgorithm, System.Text.Encoding.UTF8.GetBytes(_sharedKey));

                        // Save file
                        File.WriteAllBytes(fileName, decryptedContent);
                        Console.WriteLine("File received and verified successfully.");
                    }
                    else
                    {
                        Console.WriteLine("File verification failed.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error handling client: {ex.Message}");
            }
        }

        public async Task SendFile(string ipAddress, byte[] fileContent, string fileName, string selectedAlgorithm, string sharedKey)
        {
            try
            {
                TcpClient client = new TcpClient(ipAddress, Port);
                using (NetworkStream stream = client.GetStream())
                using (BinaryWriter writer = new BinaryWriter(stream))
                {
                    byte[] hash = ComputeSHA1Hash(fileContent);

                    writer.Write(fileName);
                    writer.Write((long)fileContent.Length);
                    writer.Write(hash.Length);
                    writer.Write(hash);
                    writer.Write(fileContent);

                    Console.WriteLine("File sent successfully.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending file: {ex.Message}");
            }
        }

        public async Task ConnectToServer(string ipAddress, string selectedAlgorithm, string sharedKey)
        {
            _selectedAlgorithm = selectedAlgorithm;
            _sharedKey = sharedKey;

            TcpClient client = new TcpClient(ipAddress, Port);
            Console.WriteLine("Connected to server.");
        }

        private byte[] ComputeSHA1Hash(byte[] data)
        {
            using (SHA1 sha1 = SHA1.Create())
            {
                return sha1.ComputeHash(data);
            }
        }
    }
}