using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace CryptographyWebApp.Services
{
    public class FileExchangeService
    {
        private TcpListener _listener;
        private int _serverPort;

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
                using (NetworkStream networkStream = client.GetStream())
                using (BinaryReader reader = new BinaryReader(networkStream))
                {
                    string fileName = reader.ReadString();
                    long fileSize = reader.ReadInt64();

                    Console.WriteLine($"Receiving file: {fileName} ({fileSize} bytes)");

                    string savePath = Path.Combine(Directory.GetCurrentDirectory(), "received_" + fileName);
                    using (FileStream fileStream = new FileStream(savePath, FileMode.Create, FileAccess.Write))
                    {
                        byte[] buffer = new byte[4096];
                        long totalBytesReceived = 0;

                        while (totalBytesReceived < fileSize)
                        {
                            int bytesRead = await networkStream.ReadAsync(buffer, 0, buffer.Length);
                            if (bytesRead == 0) break;

                            await fileStream.WriteAsync(buffer, 0, bytesRead);
                            totalBytesReceived += bytesRead;
                        }
                    }

                    Console.WriteLine($"File {fileName} successfully received.");
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

        public async Task SendFile(string ipAddress, int port, string filePath)
        {
            try
            {
                using (TcpClient client = new TcpClient(ipAddress, port))
                using (NetworkStream networkStream = client.GetStream())
                using (BinaryWriter writer = new BinaryWriter(networkStream))
                {
                    string fileName = Path.GetFileName(filePath);
                    long fileSize = new FileInfo(filePath).Length;

                    // Šaljemo metapodatke
                    writer.Write(fileName);
                    writer.Write(fileSize);

                    // Šaljemo fajl
                    using (FileStream fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                    {
                        byte[] buffer = new byte[4096];
                        int bytesRead;

                        while ((bytesRead = await fileStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                        {
                            await networkStream.WriteAsync(buffer, 0, bytesRead);
                        }
                    }

                    Console.WriteLine("File sent successfully.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending file: {ex.Message}");
            }
        }
    }
}