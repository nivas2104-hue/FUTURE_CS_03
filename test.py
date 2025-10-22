"""
Quick test to verify encryption is working
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import secrets

print("Testing AES Encryption...")
print("-" * 50)

# Test data
original_data = b"Hello, this is a test message!"
print(f"Original data: {original_data.decode()}")
print()

# Generate key and IV
key = secrets.token_bytes(32)  # 256-bit key
iv = secrets.token_bytes(16)   # 128-bit IV

# Encrypt
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()

padder = padding.PKCS7(128).padder()
padded_data = padder.update(original_data) + padder.finalize()

encrypted = encryptor.update(padded_data) + encryptor.finalize()
print(f"Encrypted data (first 50 bytes): {encrypted[:50]}")
print(f"Encrypted looks like gibberish? {not any(32 <= b <= 126 for b in encrypted[:20])}")
print()

# Decrypt
cipher2 = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
decryptor = cipher2.decryptor()

decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()

unpadder = padding.PKCS7(128).unpadder()
decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

print(f"Decrypted data: {decrypted.decode()}")
print()

# Verify
if original_data == decrypted:
    print("✅ SUCCESS! Encryption and decryption working correctly!")
else:
    print("❌ ERROR! Data doesn't match after decryption")

print("-" * 50)