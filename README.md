# 🔒 FolderLock — AES-256-GCM Folder Encryption Utility

FolderLock is a secure desktop application built with Python that encrypts entire folders into a single encrypted container using **AES-256-GCM** encryption and **PBKDF2-SHA256** key derivation.

Designed with a modern GUI and strong cryptographic practices, FolderLock provides a simple way to protect sensitive files and folders with a password.

---

## ✨ Features

* 🔐 AES-256-GCM authenticated encryption
* 🔑 PBKDF2-SHA256 key derivation (600,000 iterations)
* 📁 Encrypt entire folders into a single `.flck` container
* 📂 Restore encrypted folders with original directory structure
* ✅ Automatic integrity verification after encryption
* 🗑 Optional secure deletion of original files
* 📊 Password strength meter
* 🎨 Modern dark-themed GUI built with Tkinter
* 🚀 No external server or cloud dependency

---

## 🛡 Security

FolderLock uses modern cryptographic standards:

| Component         | Implementation                  |
| ----------------- | ------------------------------- |
| Encryption        | AES-256-GCM                     |
| Key Derivation    | PBKDF2-HMAC-SHA256              |
| Salt Length       | 32 Bytes                        |
| Nonce Length      | 12 Bytes                        |
| PBKDF2 Iterations | 600,000                         |
| Authentication    | Built-in GCM Authentication Tag |

Each encryption operation generates a unique random salt and nonce, ensuring that identical passwords never produce identical encrypted outputs.

---

## 📦 Installation

### Clone Repository

```bash
git clone https://github.com/areebxy/folderlock.git
cd folderlock
```

### Install Dependencies

```bash
pip install cryptography
```

---

## ▶ Usage

Run the application:

```bash
python folder_locker.py
```

### Encrypt a Folder

1. Select **Lock Folder**
2. Browse and choose a folder
3. Enter a password
4. Confirm password
5. Click **Lock Folder**
6. A `.flck` encrypted container will be created

### Decrypt a Folder

1. Select **Unlock File**
2. Choose a `.flck` file
3. Enter the correct password
4. Click **Unlock File**
5. Files will be restored automatically

---

## 📁 Container Format

FolderLock stores encrypted data in a custom `.flck` format:

```text
MAGIC       4 bytes
VERSION     1 byte
SALT       32 bytes
NONCE      12 bytes
DATA_LEN    8 bytes
DATA      variable
```

---

## ⚠ Important Notes

* If you forget your password, your data cannot be recovered.
* AES-GCM provides both encryption and integrity protection.
* Secure deletion effectiveness may vary depending on the operating system and storage device.
* Always keep backups of important data.

---

## 🖼 Screenshot

Add screenshots of the application here:

```text
assets/screenshot.png
```

---

## 🛠 Built With

* Python 3
* Tkinter
* Cryptography Library
* AES-256-GCM
* PBKDF2-HMAC-SHA256

---

## 📄 License

This project is licensed under the MIT License.

---

## 👨‍💻 Author

**Mohammad Areeb**

FolderLock was created to provide a simple, secure, and user-friendly way to protect sensitive folders using modern encryption standards.

---

### ⭐ If you find this project useful, consider giving it a star on GitHub!
