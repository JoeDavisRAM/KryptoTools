from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

class KeyManager:
       @staticmethod
       def generate_rsa_keypair():
           private_key = rsa.generate_private_key(
               public_exponent=65537,
               key_size=2048,
               backend=default_backend()
           )
           public_key = private_key.public_key()
           return private_key, public_key

       @staticmethod
       def generate_ecc_keypair():
           private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
           public_key = private_key.public_key()
           return private_key, public_key

       @staticmethod
       def save_private_key(private_key, filename):
           with open(filename, 'wb') as f:
               f.write(private_key.private_bytes(
                   encoding=serialization.Encoding.PEM,
                   format=serialization.PrivateFormat.TraditionalOpenSSL
               ))

       @staticmethod
       def load_private_key(filename):
           with open(filename, 'rb') as f:
               return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())