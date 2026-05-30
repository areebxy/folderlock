# 🔒 FolderLock

**AES-256-GCM Folder Encryption Utility**

FolderLock is a secure desktop application built with Python that encrypts entire folders into a single encrypted container (`.flck`) using modern cryptographic standards.

The application features a clean graphical interface, password strength analysis, integrity verification, and optional secure deletion of original files after successful encryption.

---

## ✨ Features

* 🔐 AES-256-GCM authenticated encryption
* 🔑 PBKDF2-HMAC-SHA256 key derivation (600,000 iterations)
* 📁 Encrypt entire folders into a single `.flck` file
* 📂 Restore encrypted folders with original directory structure
* ✅ Automatic integrity verification before deleting originals
* 📊 Password strength meter
* 🎨 Modern dark-themed GUI
* 🗑 Optional shredding of original files after encryption
* 💻 Cross-platform support (Windows & Linux)

---

## 🛡 Security

FolderLock uses industry-standard cryptographic primitives:

| Component               | Implementation         |
| ----------------------- | ---------------------- |
| Encryption Algorithm    | AES-256-GCM            |
| Key Derivation Function | PBKDF2-HMAC-SHA256     |
| PBKDF2 Iterations       | 600,000                |
| Salt Length             | 32 Bytes               |
| Nonce Length            | 12 Bytes               |
| Authentication          | GCM Authentication Tag |

### Encryption Process

1. Folder contents are compressed into an in-memory ZIP archive.
2. A random salt and nonce are generated.
3. A 256-bit key is derived from the user's password.
4. ZIP data is encrypted using AES-256-GCM.
5. The encrypted data is stored inside a `.flck` container.
6. Integrity is verified before any optional deletion of original files.

---

## 📦 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/areebxy/Folder-Lock.git
cd Folder-Lock
```

---

## 🪟 Windows Installation

### Install Python

Download and install Python from:

https://www.python.org/downloads/

During installation, make sure to enable:

```text
☑ Add Python to PATH
```

### Install Dependencies

Open Command Prompt or PowerShell:

```bash
pip install cryptography
```

### Run the Application

```bash
python main.py
```

---

## 🐧 Linux Installation

### Ubuntu / Debian / Kali Linux

Install Tkinter and required packages:

```bash
sudo apt update
sudo apt install python3 python3-pip python3-tk -y
pip3 install cryptography
```

Run:

```bash
python3 main.py
```

---

### Fedora

```bash
sudo dnf install python3 python3-pip python3-tkinter
pip3 install cryptography
```

Run:

```bash
python3 main.py
```

---

### Arch Linux

```bash
sudo pacman -S python python-pip tk
pip install cryptography
```

Run:

```bash
python main.py
```

---

## 🚀 Usage

### Encrypt a Folder

1. Launch FolderLock.
2. Select **Lock Folder**.
3. Browse and choose a folder.
4. Enter a strong password.
5. Confirm the password.
6. Click **Lock Folder**.
7. A `.flck` encrypted container will be generated.

### Decrypt a Folder

1. Launch FolderLock.
2. Select **Unlock File**.
3. Browse and select a `.flck` file.
4. Enter the correct password.
5. Click **Unlock File**.
6. The folder contents will be restored.

---

## 📁 File Format

FolderLock stores encrypted data using the following format:

```text
MAGIC       4 bytes
VERSION     1 byte
SALT       32 bytes
NONCE      12 bytes
DATA_LEN    8 bytes
DATA      variable length
```

---

## ⚠ Important Notes

* Password recovery is impossible if the password is lost.
* AES-GCM provides both confidentiality and integrity protection.
* Always keep backups of important files.
* Secure deletion behavior depends on the operating system and storage device.

---

## 📂 Project Structure

```text
Folder-Lock/
│
├── main.py
├── README.md
└── screenshots/
```

---

## 📸 Screenshots

<img width="692" height="820" alt="image" src="https://github.com/user-attachments/assets/fe292640-9f78-4c1e-869e-944e1f557d0a" />

---

## 🛠 Requirements

* Python 3.10+
* cryptography

Install manually:

```bash
pip install cryptography
```

---

## 👨‍💻 Author

**Mohammad Areeb**

GitHub: https://github.com/areebxy

---

## ⭐ Support

If you find this project useful:

* ⭐ Star the repository
* 🍴 Fork the project
* 🛠 Contribute improvements
* 🐞 Report bugs through GitHub Issues

---

## 📜 License

This project is licensed under the MIT License.
