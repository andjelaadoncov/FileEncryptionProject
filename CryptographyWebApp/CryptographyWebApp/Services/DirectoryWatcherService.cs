using System.IO;
using CryptographyWebApp.Services;

namespace CryptographyWebApp.Services
{
    public class DirectoryWatcherService
    {
        private readonly FileSystemWatcher _fileWatcher;
        private readonly CryptoService _cryptoService;
        private readonly string _targetDirectory;
        private readonly string _outputDirectory;
        private string _algorithm;
        private byte[] _sharedKey;
        public event Action FilesChanged;

        public string OutputDirectory => _outputDirectory;
        public string TargetDirectory => _targetDirectory;

        public DirectoryWatcherService(string targetDirectory, string outputDirectory, CryptoService cryptoService)
        {
            _targetDirectory = targetDirectory;
            _outputDirectory = outputDirectory;
            _cryptoService = cryptoService;

            _fileWatcher = new FileSystemWatcher(targetDirectory)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size,
                Filter = "*.*", // pracenje svih fajlova
                EnableRaisingEvents = false // inicijalno disable
            };

            _fileWatcher.Created += OnFileCreated;
        }

        public void Update(byte[] newKey, string chosenAlgorithm)
        {
            _sharedKey = newKey;
            _algorithm = chosenAlgorithm;
        }


        private void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            try
            {
                string filePath = e.FullPath;

                // cekanje da fajl bude dostupan
                Task.Delay(200).Wait();

                byte[] fileData = File.ReadAllBytes(filePath);
                string originalExtension = Path.GetExtension(filePath);

                // kodiranje originalne ekstenzije kao zaglavlje fiksne duzine 
                byte[] extensionBytes = System.Text.Encoding.UTF8.GetBytes(originalExtension.PadRight(20, '\0'));
                byte[] combinedData = new byte[extensionBytes.Length + fileData.Length];
                Buffer.BlockCopy(extensionBytes, 0, combinedData, 0, extensionBytes.Length);
                Buffer.BlockCopy(fileData, 0, combinedData, extensionBytes.Length, fileData.Length);

                byte[] encryptedData = _cryptoService.EncryptFile(combinedData, _algorithm, _sharedKey);

                // kljuc u Keys folderu
                string keyFolderPath = Path.Combine(AppContext.BaseDirectory, "Keys");
                if (!Directory.Exists(keyFolderPath))
                {
                    Directory.CreateDirectory(keyFolderPath);
                }

                string keyFileName = Path.GetFileNameWithoutExtension(filePath) + "_encrypted.key";
                string keyFilePath = Path.Combine(keyFolderPath, keyFileName);
                File.WriteAllBytes(keyFilePath, _sharedKey);

                string outputFilePath = Path.Combine(_outputDirectory, Path.GetFileNameWithoutExtension(filePath) + "_encrypted.dat");
                File.WriteAllBytes(outputFilePath, encryptedData);

                FilesChanged?.Invoke(); // refresh za display
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing file {e.FullPath}: {ex.Message}");
            }
        }


        public void StartWatching() => _fileWatcher.EnableRaisingEvents = true;

        public void StopWatching() => _fileWatcher.EnableRaisingEvents = false;
    }
}

