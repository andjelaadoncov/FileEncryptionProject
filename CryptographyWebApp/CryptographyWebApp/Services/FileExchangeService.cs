using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptographyWebApp.Services
{
    public class FileExchangeService
    {
        private TcpListener _listener;
        private int _serverPort;
        private readonly CryptoService _cryptoService = new CryptoService();
        private CancellationTokenSource _cancellationTokenSource;
        public Action<string> OnFileReceived;

        public async Task StartServer(int port)
        {
            _serverPort = port;
            _cancellationTokenSource = new CancellationTokenSource();
            _listener = new TcpListener(IPAddress.Any, _serverPort);
            _listener.Start();
            Console.WriteLine($"Server started on port {_serverPort}...");

            try
            {
                while (!_cancellationTokenSource.Token.IsCancellationRequested)
                {
                    if (_listener.Pending())
                    {
                        TcpClient client = await _listener.AcceptTcpClientAsync();
                        _ = HandleClientAsync(client);
                    }
                    else
                    {
                        await Task.Delay(100); // da ne troši CPU bespotrebno
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Server exception: {ex.Message}");
            }
        }


        public void StopServer()
        {
            try
            {
                _cancellationTokenSource?.Cancel();
                _listener?.Stop();
                Console.WriteLine("Server stopped.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error stopping server: {ex.Message}");
            }
        }

        private async Task HandleClientAsync(TcpClient client)
        {
            try
            {
                Console.WriteLine("Client connected. Waiting for public key...");
                NetworkStream networkStream = client.GetStream();
                using (BinaryReader reader = new BinaryReader(networkStream))
                using (BinaryWriter writer = new BinaryWriter(networkStream)) // Create writer here
                {
                    // Receive public key from client
                    int clientPublicKeyLength = reader.ReadInt32();
                    byte[] clientPublicKey = reader.ReadBytes(clientPublicKeyLength);
                    Console.WriteLine($"Received client public key: {clientPublicKey.Length} bytes");

                    // Generate server's public key
                    using (ECDiffieHellmanCng diffieHellman = new ECDiffieHellmanCng())
                    {
                        byte[] serverPublicKey = diffieHellman.PublicKey.ToByteArray();
                        Console.WriteLine($"Generated server public key: {serverPublicKey.Length} bytes");

                        // Send server's public key to client
                        writer.Write(serverPublicKey.Length);
                        writer.Write(serverPublicKey);
                        writer.Flush(); // Ensure data is sent
                        Console.WriteLine("Sent server public key to client.");

                        // Derive shared secret
                        byte[] sharedSecret = diffieHellman.DeriveKeyMaterial(CngKey.Import(clientPublicKey, CngKeyBlobFormat.EccPublicBlob));
                        Console.WriteLine("Derived shared secret.");

                        // Receive file metadata
                        string fileName = reader.ReadString(); // Read file name
                        long fileSize = reader.ReadInt64(); // Server sada prima ispravnu dužinu fajla
                        int hashLength = reader.ReadInt32();
                        byte[] receivedHash = reader.ReadBytes(hashLength);
                        string algorithm = reader.ReadString(); // Čita ime algoritma

                        Console.WriteLine($"Received file metadata: {fileName}, {fileSize} bytes, hash length: {hashLength}");

                        // Receive encrypted file data
                        byte[] encryptedFileData = reader.ReadBytes((int)fileSize);
                        Console.WriteLine($"Received encrypted file data: {encryptedFileData.Length} bytes");

                        // Decrypt file data
                        byte[] decryptedFileData = _cryptoService.DecryptFile(encryptedFileData, algorithm, sharedSecret);
                        Console.WriteLine("Decrypted file data.");

                        // Compute SHA-1 hash of the decrypted file data
                        byte[] computedHash;
                        using (SHA1 sha1 = SHA1.Create())
                        {
                            computedHash = sha1.ComputeHash(decryptedFileData);
                        }
                        Console.WriteLine("Computed hash of decrypted file data.");

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
                        OnFileReceived?.Invoke(fileName);
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
                Console.WriteLine("Client connection closed.");
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
                        Console.WriteLine($"Generated client public key: {clientPublicKey.Length} bytes");

                        // Send client's public key to server
                        writer.Write(clientPublicKey.Length);
                        writer.Write(clientPublicKey);
                        Console.WriteLine("Sent client public key to server.");

                        // Receive server's public key
                        using (BinaryReader reader = new BinaryReader(networkStream))
                        {
                            int serverPublicKeyLength = reader.ReadInt32();
                            byte[] serverPublicKey = reader.ReadBytes(serverPublicKeyLength);
                            Console.WriteLine($"Received server public key: {serverPublicKey.Length} bytes");

                            // Derive shared secret
                            byte[] sharedSecret = diffieHellman.DeriveKeyMaterial(CngKey.Import(serverPublicKey, CngKeyBlobFormat.EccPublicBlob));
                            Console.WriteLine("Derived shared secret.");

                            // Read file data
                            byte[] fileData = await File.ReadAllBytesAsync(filePath);
                            if (algorithm == "Bifid") //ovo sam dodala jer bifid radi drugacije od ostalih
                            {
                                fileData = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(fileData).ToUpper());
                            }

                            string fileName = Path.GetFileName(filePath);
                            Console.WriteLine($"Read file data: {fileName}, {fileData.Length} bytes");

                            // Encrypt file data
                            byte[] encryptedFileData = _cryptoService.EncryptFile(fileData, algorithm, sharedSecret);
                            Console.WriteLine($"Encrypted file data: {encryptedFileData.Length} bytes");

                            // Compute SHA-1 hash of the original file data
                            byte[] fileHash;
                            using (SHA1 sha1 = SHA1.Create())
                            {
                                fileHash = sha1.ComputeHash(fileData);
                            }
                            Console.WriteLine("Computed file hash.");

                            // Send file metadata
                            writer.Write(fileName); // Send file name
                            writer.Write((long)encryptedFileData.Length); //Sada šaljemo long
                            writer.Write(fileHash.Length); // Send hash length
                            writer.Write(fileHash); // Send hash
                            writer.Write(algorithm); // Dodajemo algoritam u metapodatke
                            Console.WriteLine("Sent file metadata.");

                            // Send encrypted file data
                            writer.Write(encryptedFileData);
                            Console.WriteLine("Sent encrypted file data.");

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