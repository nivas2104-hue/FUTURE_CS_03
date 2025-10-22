from flask import Flask, render_template, request, send_file, jsonify, session
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import secrets
import hashlib
from datetime import datetime
import json

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configuration
UPLOAD_FOLDER = 'encrypted_files'
KEYS_FOLDER = 'encryption_keys'
METADATA_FILE = 'files_metadata.json'

# Create necessary directories
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(KEYS_FOLDER, exist_ok=True)

# Initialize metadata file
if not os.path.exists(METADATA_FILE):
    with open(METADATA_FILE, 'w') as f:
        json.dump({}, f)

class FileEncryptor:
    """Handles AES-256 encryption and decryption of files"""
    
    @staticmethod
    def generate_key():
        """Generate a random 256-bit encryption key"""
        return secrets.token_bytes(32)
    
    @staticmethod
    def encrypt_file(file_data, key):
        """Encrypt file data using AES-256-CBC"""
        # Generate random IV
        iv = secrets.token_bytes(16)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Pad data to AES block size (128 bits = 16 bytes)
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        
        # Encrypt
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV + encrypted data
        return iv + encrypted_data
    
    @staticmethod
    def decrypt_file(encrypted_data, key):
        """Decrypt file data using AES-256-CBC"""
        # Extract IV (first 16 bytes)
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpad
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        return data

class KeyManager:
    """Manages encryption keys securely"""
    
    @staticmethod
    def save_key(file_id, key):
        """Save encryption key with file ID"""
        key_path = os.path.join(KEYS_FOLDER, f"{file_id}.key")
        with open(key_path, 'wb') as f:
            f.write(key)
    
    @staticmethod
    def load_key(file_id):
        """Load encryption key for file ID"""
        key_path = os.path.join(KEYS_FOLDER, f"{file_id}.key")
        if os.path.exists(key_path):
            with open(key_path, 'rb') as f:
                return f.read()
        return None

class MetadataManager:
    """Manages file metadata"""
    
    @staticmethod
    def add_file(file_id, original_name, size):
        """Add file metadata"""
        with open(METADATA_FILE, 'r') as f:
            metadata = json.load(f)
        
        metadata[file_id] = {
            'original_name': original_name,
            'size': size,
            'upload_time': datetime.now().isoformat(),
            'encrypted_path': os.path.join(UPLOAD_FOLDER, f"{file_id}.enc")
        }
        
        with open(METADATA_FILE, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    @staticmethod
    def get_all_files():
        """Get all file metadata"""
        with open(METADATA_FILE, 'r') as f:
            return json.load(f)
    
    @staticmethod
    def get_file(file_id):
        """Get specific file metadata"""
        metadata = MetadataManager.get_all_files()
        return metadata.get(file_id)
    
    @staticmethod
    def delete_file(file_id):
        """Delete file metadata"""
        with open(METADATA_FILE, 'r') as f:
            metadata = json.load(f)
        
        if file_id in metadata:
            del metadata[file_id]
        
        with open(METADATA_FILE, 'w') as f:
            json.dump(metadata, f, indent=2)

@app.route('/')
def index():
    """Render main page"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and encryption"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Read file data
        file_data = file.read()
        original_size = len(file_data)
        
        # Generate unique file ID
        file_id = secrets.token_hex(16)
        
        # Generate encryption key
        encryption_key = FileEncryptor.generate_key()
        
        # Encrypt file
        encrypted_data = FileEncryptor.encrypt_file(file_data, encryption_key)
        
        # Save encrypted file
        encrypted_path = os.path.join(UPLOAD_FOLDER, f"{file_id}.enc")
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Save encryption key
        KeyManager.save_key(file_id, encryption_key)
        
        # Save metadata
        MetadataManager.add_file(file_id, file.filename, original_size)
        
        return jsonify({
            'success': True,
            'file_id': file_id,
            'filename': file.filename,
            'size': original_size
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download/<file_id>')
def download_file(file_id):
    """Handle file download and decryption"""
    try:
        # Get file metadata
        file_info = MetadataManager.get_file(file_id)
        
        if not file_info:
            return jsonify({'error': 'File not found'}), 404
        
        # Load encryption key
        encryption_key = KeyManager.load_key(file_id)
        
        if not encryption_key:
            return jsonify({'error': 'Encryption key not found'}), 404
        
        # Read encrypted file
        encrypted_path = file_info['encrypted_path']
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt file
        decrypted_data = FileEncryptor.decrypt_file(encrypted_data, encryption_key)
        
        # Save decrypted file temporarily
        temp_path = os.path.join(UPLOAD_FOLDER, f"temp_{file_id}")
        with open(temp_path, 'wb') as f:
            f.write(decrypted_data)
        
        # Send file
        response = send_file(
            temp_path,
            as_attachment=True,
            download_name=file_info['original_name']
        )
        
        # Clean up temp file after sending
        @response.call_on_close
        def cleanup():
            if os.path.exists(temp_path):
                os.remove(temp_path)
        
        return response
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/files')
def list_files():
    """List all uploaded files"""
    try:
        files = MetadataManager.get_all_files()
        return jsonify({'files': files})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/delete/<file_id>', methods=['DELETE'])
def delete_file(file_id):
    """Delete a file and its encryption key"""
    try:
        # Get file info
        file_info = MetadataManager.get_file(file_id)
        
        if not file_info:
            return jsonify({'error': 'File not found'}), 404
        
        # Delete encrypted file
        if os.path.exists(file_info['encrypted_path']):
            os.remove(file_info['encrypted_path'])
        
        # Delete encryption key
        key_path = os.path.join(KEYS_FOLDER, f"{file_id}.key")
        if os.path.exists(key_path):
            os.remove(key_path)
        
        # Delete metadata
        MetadataManager.delete_file(file_id)
        
        return jsonify({'success': True})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)