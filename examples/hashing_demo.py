"""
Hashing Demo

Demonstrates cryptographic hashing functions.
"""

from crypto_tools.hashing import sha256, sha512, bcrypt_hash, bcrypt_verify

def main():
    # SHA-256 and SHA-512 examples
    print("=== SHA Hashing ===")
    data = "Hello, world!"
    print(f"Original data: {data}")
    
    sha256_hash = sha256(data)
    print(f"SHA-256: {sha256_hash}")
    
    sha512_hash = sha512(data)
    print(f"SHA-512: {sha512_hash}")
    
    # With salt
    salted_sha256 = sha256(data, salt="random_salt")
    print(f"Salted SHA-256: {salted_sha256}")
    
    # Bcrypt examples
    print("\n=== Bcrypt Password Hashing ===")
    password = "my_secure_password"
    print(f"Original password: {password}")
    
    hashed = bcrypt_hash(password)
    print(f"Hashed password: {hashed}")
    
    # Verification
    print("\n=== Password Verification ===")
    test_password = "my_secure_password"
    is_valid = bcrypt_verify(test_password, hashed)
    print(f"Password '{test_password}' is valid: {is_valid}")
    
    wrong_password = "wrong_password"
    is_valid = bcrypt_verify(wrong_password, hashed)
    print(f"Password '{wrong_password}' is valid: {is_valid}")

if __name__ == "__main__":
    main()