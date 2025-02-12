using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace CryptographyWebApp.Services
{
    public class FileExchangeService
    {
        private TcpListener _listener;
        private int _serverPort;
        private readonly CryptoService _cryptoService = new CryptoService();

        public async Task StartServer(int port)
        {
            _serverPort = port;
            _listener = new TcpListener(IPAddress.Any, _serverPort);
            _listener.Start();
            Console.WriteLine($"Server started on port {_serverPort}...");

            while (true)
            {
                TcpClient client = await _listener.AcceptTcpClientAsync();
                _ = HandleClientAsync(client);
            }
        }

        private async Task HandleClientAsync(TcpClient client)
        {
            try
            {
                using (client)
                using (NetworkStream networkStream = client.GetStream())
                using (BinaryReader reader = new BinaryReader(networkStream))
                {
                    // Receive public key from client
                    byte[] clientPublicKey = reader.ReadBytes(reader.ReadInt32());

                    // Generate server's public key
                    using (ECDiffieHellmanCng diffieHellman = new ECDiffieHellmanCng())
                    {
                        byte[] serverPublicKey = diffieHellman.PublicKey.ToByteArray();

                        // Send server's public key to client
                        using (BinaryWriter writer = new BinaryWriter(networkStream))
                        {
                            writer.Write(serverPublicKey.Length);
                            writer.Write(serverPublicKey);
                        }

                        // Derive shared secret
                        byte[] sharedSecret = diffieHellman.DeriveKeyMaterial(CngKey.Import(clientPublicKey, CngKeyBlobFormat.EccPublicBlob));

                        // Receive file metadata
                        string fileName = reader.ReadString();
                        long fileSize = reader.ReadInt64();
                        int hashLength = reader.ReadInt32();
                        byte[] receivedHash = reader.ReadBytes(hashLength);

                        Console.WriteLine($"Receiving file: {fileName} ({fileSize} bytes)");

                        // Receive encrypted file data
                        byte[] encryptedFileData = reader.ReadBytes((int)fileSize);

                        // Decrypt file data
                        byte[] decryptedFileData = _cryptoService.DecryptFile(encryptedFileData, "RC6", sharedSecret);

                        // Compute SHA-1 hash of the decrypted file data
                        byte[] computedHash;
                        using (SHA1 sha1 = SHA1.Create())
                        {
                            computedHash = sha1.ComputeHash(decryptedFileData);
                        }

                        // Verify file integrity
                        if (!computedHash.SequenceEqual(receivedHash))
                        {
                            Console.WriteLine("File integrity check failed.");
                            return;
                        }

                        // Save the decrypted file
                        string savePath = Path.Combine(Directory.GetCurrentDirectory(), "received_" + fileName);
                        await File.WriteAllBytesAsync(savePath, decryptedFileData);

                        Console.WriteLine($"File {fileName} successfully received and decrypted.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error handling client: {ex.Message}");
            }
            finally
            {
                client.Close();
            }
        }

        public async Task SendFile(string ipAddress, int port, string filePath, string algorithm)
        {
            try
            {
                using (TcpClient client = new TcpClient(ipAddress, port))
                using (NetworkStream networkStream = client.GetStream())
                using (BinaryWriter writer = new BinaryWriter(networkStream))
                {
                    // Generate client's public key
                    using (ECDiffieHellmanCng diffieHellman = new ECDiffieHellmanCng())
                    {
                        byte[] clientPublicKey = diffieHellman.PublicKey.ToByteArray();

                        // Send client's public key to server
                        writer.Write(clientPublicKey.Length);
                        writer.Write(clientPublicKey);

                        // Receive server's public key
                        using (BinaryReader reader = new BinaryReader(networkStream))
                        {
                            int serverPublicKeyLength = reader.ReadInt32();
                            byte[] serverPublicKey = reader.ReadBytes(serverPublicKeyLength);

                            // Derive shared secret
                            byte[] sharedSecret = diffieHellman.DeriveKeyMaterial(CngKey.Import(serverPublicKey, CngKeyBlobFormat.EccPublicBlob));

                            // Read file data
                            byte[] fileData = await File.ReadAllBytesAsync(filePath);
                            string fileName = Path.GetFileName(filePath);

                            // Encrypt file data
                            byte[] encryptedFileData = _cryptoService.EncryptFile(fileData, algorithm, sharedSecret);

                            // Compute SHA-1 hash of the original file data
                            byte[] fileHash;
                            using (SHA1 sha1 = SHA1.Create())
                            {
                                fileHash = sha1.ComputeHash(fileData);
                            }

                            // Send file metadata
                            writer.Write(fileName);
                            writer.Write(encryptedFileData.Length);
                            writer.Write(fileHash.Length);
                            writer.Write(fileHash);

                            // Send encrypted file data
                            writer.Write(encryptedFileData);

                            Console.WriteLine("File sent successfully.");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending file: {ex.Message}");
            }
        }
    }
}