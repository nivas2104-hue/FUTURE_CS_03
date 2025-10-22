# 🔐 Secure File Encryption Portal

A Flask-based web application that provides military-grade AES-256-CBC encryption for file uploads. Upload any file, and it's automatically encrypted before storage. Download files seamlessly with automatic decryption.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/flask-3.0.0-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## ✨ Features

- 🔒 **AES-256-CBC Encryption** - Military-grade security for all uploaded files
- 🔑 **Unique Encryption Keys** - Each file gets its own encryption key
- 🎯 **Seamless UX** - Files are encrypted on upload, decrypted on download
- 🗑️ **Secure Deletion** - Remove files and keys permanently
- 📁 **File Isolation** - Encrypted files and keys stored separately
- 🌐 **Modern UI** - Clean, responsive web interface
- 🚀 **Lightweight** - Minimal dependencies, easy to deploy

## 🔐 How It Works

| Stage | Location | Content | Status |
|-------|----------|---------|--------|
| **Upload** | Client → Server | Original file | Processing |
| **Encryption** | Server | AES-256-CBC applied | Encrypting |
| **Storage** | `encrypted_files/*.enc` | Encrypted gibberish | **Secure** ✅ |
| **Download** | Server → Client | Decrypted content | **Restored** ✅ |

**Security Guarantee**: Stored `.enc` files are completely unreadable without the encryption key. Even if someone accesses your server, they cannot read the file contents.

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/nivas2104-hue/FUTURE_CS_03.git
cd FUTURE_CS_03
```

2. **Create a virtual environment**
```bash
python -m venv venv
```

3. **Activate virtual environment**

**Windows:**
```bash
venv\Scripts\activate
```

**Mac/Linux:**
```bash
source venv/bin/activate
```

4. **Install dependencies**
```bash
pip install -r requirements.txt
```

5. **Run the application**
```bash
python app.py
```

6. **Open in browser**
```
http://127.0.0.1:5000
```

## 📂 Project Structure

```
secure-file-encryption-portal/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── templates/
│   └── index.html        # Web interface
├── encrypted_files/      # Encrypted files (auto-created)
├── encryption_keys/      # Encryption keys (auto-created)
└── venv/                 # Virtual environment (after setup)
```

## 🎯 Usage

### Upload & Encrypt
1. Click the purple upload box or drag-and-drop a file
2. Click **"Upload & Encrypt"**
3. File is encrypted with AES-256 and stored securely

### Download & Decrypt
1. Click the green **"📥 Download"** button on any file
2. File is automatically decrypted and downloaded
3. Original content is restored perfectly

### Delete Files
1. Click the red **"🗑️ Delete"** button
2. Both encrypted file and encryption key are permanently removed

## 🔒 Security Features

✅ **AES-256-CBC Encryption** - Industry-standard symmetric encryption  
✅ **Unique Keys Per File** - Each file has its own encryption key  
✅ **Key Isolation** - Keys stored separately from encrypted files  
✅ **Secure Random Keys** - Cryptographically secure key generation  
✅ **IV (Initialization Vector)** - Prevents pattern detection in encrypted data  
✅ **No Plaintext Storage** - Original files never stored unencrypted  

## 🛠️ Configuration

### Change Port
Edit `app.py`, last line:
```python
app.run(debug=True, port=8000)  # Change from 5000 to 8000
```

### Modify Upload Folder
Edit `app.py`:
```python
UPLOAD_FOLDER = 'my_encrypted_files'
KEYS_FOLDER = 'my_keys'
```

## 📋 Requirements

```
Flask==3.0.0
cryptography==41.0.7
```

## ⚠️ Troubleshooting

### "python is not recognized"
**Fix**: Install Python from [python.org](https://www.python.org/downloads/) and check "Add Python to PATH" during installation.

### Can't activate virtual environment (Windows)
**Fix**: Run PowerShell as Administrator and execute:
```bash
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Port 5000 already in use
**Fix**: Change the port in `app.py` (see Configuration section above).

### "Module not found" error
**Fix**: Ensure virtual environment is activated and run:
```bash
pip install -r requirements.txt
```

## 🧪 Testing Encryption

1. **Create a test file** with readable content:
   ```
   This is my secret message!
   Password: 12345
   ```

2. **Upload it** through the portal

3. **Check encrypted file**:
   - Navigate to `encrypted_files/`
   - Open the `.enc` file
   - You should see gibberish: `;è®ý§èRyÍÈ´› ~D26³j•kÝô` ✅

4. **Download and verify**:
   - Download the file from the portal
   - Open it - you should see the original readable text ✅

## 🚨 Important Security Notes

⚠️ **Key Management**: Encryption keys are stored on the server. In production, use a dedicated key management system (AWS KMS, Azure Key Vault, HashiCorp Vault).

⚠️ **Access Control**: Currently no authentication. Add user management for multi-user environments.





## 🙏 Acknowledgments

- Built with [Flask](https://flask.palletsprojects.com/)
- Encryption powered by [cryptography](https://cryptography.io/)


## 📧 Contact

Nivas - GitHub: [@nivas2104-hue](https://github.com/nivas2104-hue)

Project Link: [https://github.com/nivas2104-hue/FUTURE_CS_03](https://github.com/nivas2104-hue/FUTURE_CS_03)

---

