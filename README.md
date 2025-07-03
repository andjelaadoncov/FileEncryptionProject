**FileEncryptionProject** is a web application built using **C#** and **Blazor (HTML + CSS)** that enables users to encrypt, decrypt, and securely exchange files using various cryptographic algorithms.

---

## 🔍 Overview

This application allows users to:
- Encrypting files using custom and standard algorithms
- Decrypting encrypted files with the correct key and algorithm
- Exchanging encrypted files between users over a secure TCP connection
- Verify file integrity using SHA-1 hashing
- Automatically encrypt new added files with File System Watcher

Users select files through the file explorer, choose an encryption algorithm and the file is encrypted with a specific key (safety net), that can later be decrypted.

---

## ✨ Features

- 🔐 **File Encryption** – Select a file via the file explorer and encrypt it with a chosen algorithm 
- 🔓 **File Decryption** – Restore the original content with the correct key and algorithm
- 🔁 **Encrypted File Exchange** – Send and receive encrypted files between users
- ✅ **Integrity Check** – Verifies file integrity using SHA-1 hash comparison
- 📂 **Automatic Encryption** – New files in a watched directory are automatically encrypted  
- 🖥️ **User-friendly Interface** – Clean and simple UI built with Blazor 

---

## 🔧 Technologies Used

- **C#**
- **Blazor WebAssembly**
- **HTML + CSS**
- **TCP Sockets**
- **Custom CryptoService**
- **FileSystemWatcher** (.NET)

---

## 🔐 Supported Algorithms

- **RC6**
- **RC6 in OFB mode**
- **Bifid cipher**

Each algorithm is implemented as part of a modular CryptoService, allowing for easy future expansion.

---
