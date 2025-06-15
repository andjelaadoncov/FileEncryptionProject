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
                        await Task.Delay(100); // da ne trosi CPU bespotrebno
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
                using (BinaryWriter writer = new BinaryWriter(networkStream)) 
                {
                    // dobijanje public key-a od klijenta
                    int clientPublicKeyLength = reader.ReadInt32();
                    byte[] clientPublicKey = reader.ReadBytes(clientPublicKeyLength);
                    Console.WriteLine($"Received client public key: {clientPublicKey.Length} bytes");

                    // generisanje serverskog public key-a
                    using (ECDiffieHellmanCng diffieHellman = new ECDiffieHellmanCng())
                    {
                        byte[] serverPublicKey = diffieHellman.PublicKey.ToByteArray();
                        Console.WriteLine($"Generated server public key: {serverPublicKey.Length} bytes");

                        // slanje serverskog public keya do klijenta
                        writer.Write(serverPublicKey.Length);
                        writer.Write(serverPublicKey);
                        writer.Flush();
                        Console.WriteLine("Sent server public key to client.");

                        // izvedi zajednicki tajni kljuc
                        byte[] sharedSecret = diffieHellman.DeriveKeyMaterial(CngKey.Import(clientPublicKey, CngKeyBlobFormat.EccPublicBlob));
                        Console.WriteLine("Derived shared secret.");

                        // dobijanje file metadata
                        string fileName = reader.ReadString(); 
                        long fileSize = reader.ReadInt64(); // server sada prima ispravnu duzinu fajla
                        int hashLength = reader.ReadInt32();
                        byte[] receivedHash = reader.ReadBytes(hashLength);
                        string algorithm = reader.ReadString(); // cita ime algoritma

                        Console.WriteLine($"Received file metadata: {fileName}, {fileSize} bytes, hash length: {hashLength}");

                        // dobijanje ekriptovanog sadrzaja
                        byte[] encryptedFileData = reader.ReadBytes((int)fileSize);
                        Console.WriteLine($"Received encrypted file data: {encryptedFileData.Length} bytes");

                        // dekripcija sadrzaja
                        byte[] decryptedFileData = _cryptoService.DecryptFile(encryptedFileData, algorithm, sharedSecret);
                        Console.WriteLine("Decrypted file data.");

                        // racunanje SHA-1 hash za dekriptovan sadrzaj
                        byte[] computedHash;
                        using (SHA1 sha1 = SHA1.Create())
                        {
                            computedHash = sha1.ComputeHash(decryptedFileData);
                        }
                        Console.WriteLine("Computed hash of decrypted file data.");

                        //  provera integriteta
                        if (!computedHash.SequenceEqual(receivedHash))
                        {
                            Console.WriteLine("File integrity check failed.");
                            return;
                        }

                        // cuvanje
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
                    // generisanje klijentskog kljuca
                    using (ECDiffieHellmanCng diffieHellman = new ECDiffieHellmanCng())
                    {
                        byte[] clientPublicKey = diffieHellman.PublicKey.ToByteArray();
                        Console.WriteLine($"Generated client public key: {clientPublicKey.Length} bytes");

                        // posalji klijentov kljuc do servera
                        writer.Write(clientPublicKey.Length);
                        writer.Write(clientPublicKey);
                        Console.WriteLine("Sent client public key to server.");

                        // primi serverski public key
                        using (BinaryReader reader = new BinaryReader(networkStream))
                        {
                            int serverPublicKeyLength = reader.ReadInt32();
                            byte[] serverPublicKey = reader.ReadBytes(serverPublicKeyLength);
                            Console.WriteLine($"Received server public key: {serverPublicKey.Length} bytes");

                            // izvedi zajednicki tajni kljuc
                            byte[] sharedSecret = diffieHellman.DeriveKeyMaterial(CngKey.Import(serverPublicKey, CngKeyBlobFormat.EccPublicBlob));
                            Console.WriteLine("Derived shared secret.");

                            
                            byte[] fileData = await File.ReadAllBytesAsync(filePath);
                            if (algorithm == "Bifid") //ovo sam dodala jer bifid radi drugacije od ostalih
                            {
                                fileData = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(fileData).ToUpper());
                            }

                            string fileName = Path.GetFileName(filePath);
                            Console.WriteLine($"Read file data: {fileName}, {fileData.Length} bytes");

                            // enkripcija sadrzaja
                            byte[] encryptedFileData = _cryptoService.EncryptFile(fileData, algorithm, sharedSecret);
                            Console.WriteLine($"Encrypted file data: {encryptedFileData.Length} bytes");

                            // racunanje SHA-1 hash za originalni sadrzaj
                            byte[] fileHash;
                            using (SHA1 sha1 = SHA1.Create())
                            {
                                fileHash = sha1.ComputeHash(fileData);
                            }
                            Console.WriteLine("Computed file hash.");

                            // slanje file metadata
                            writer.Write(fileName); 
                            writer.Write((long)encryptedFileData.Length); // saljemo long
                            writer.Write(fileHash.Length); // saljem hash length
                            writer.Write(fileHash); // saljem hash
                            writer.Write(algorithm); // dodavanje algoritam u metapodatke
                            Console.WriteLine("Sent file metadata.");

                            // slanje fajla koji je ekriptovan
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