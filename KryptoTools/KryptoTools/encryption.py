from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class EncryptionManager:
       @staticmethod
       def encrypt_rsa(public_key, message):
           ciphertext = public_key.encrypt(
               message,
               padding.OAEP(
                   mgf=padding.MGF1(algorithm=hashes.SHA256()),
                   algorithm=hashes.SHA256(),
                   label=None
               )
           )
           return ciphertext

       @staticmethod
       def decrypt_rsa(private_key, ciphertext):
           plaintext = private_key.decrypt(
               ciphertext,
               padding.OAEP(
                   mgf=padding.MGF1(algorithm=hashes.SHA256()),
                   algorithm=hashes.SHA256(),
                   label=None
               )
           )
           return plaintext

       @staticmethod
       def encrypt_aes(key, plaintext):
           iv = os.urandom(16)
           cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
           encryptor = cipher.encryptor()
           ciphertext = iv + encryptor.update(plaintext) + encryptor.finalize()
           return ciphertext

       @staticmethod
       def decrypt_aes(key, ciphertext):
           iv = ciphertext[:16]
           cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
           decryptor = cipher.decryptor()
           plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
           return plaintext