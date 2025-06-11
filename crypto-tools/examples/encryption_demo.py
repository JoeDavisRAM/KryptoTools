"""
Encryption Demo
"""

from crypto_tools.encryption import ECC
# Initialize ECC
ecc = ECC()

# Example 1: Key generation and message signing
print("=== Example 1: Signing and Verification ===")
private_key, public_key = ecc.generate_key_pair()
print(f"Private Key:\n{private_key.decode()}")
print(f"\nPublic Key:\n{public_key.decode()}")

message = "Important secret message"
signature = ecc.sign(message, private_key)
print(f"\nSignature (hex): {signature.hex()}")

# Verify signature
verified = ecc.verify(message, signature, public_key)
print(f"Signature verification: {'Success' if verified else 'Failed'}")

# Try to verify with tampered message
fake_message = "Tampered message"
verified_fake = ecc.verify(fake_message, signature, public_key)
print(f"Tampered message verification: {'Success' if verified_fake else 'Failed'}")

# Example 2: ECDH Key Exchange
print("\n=== Example 2: ECDH Key Exchange ===")
# Generate keys for Alice and Bob
alice_priv, alice_pub = ecc.generate_key_pair()
bob_priv, bob_pub = ecc.generate_key_pair()

# Alice computes shared secret
alice_shared = ecc.derive_shared_key(alice_priv, bob_pub)
print(f"Alice's shared secret: {alice_shared.hex()}")

# Bob computes shared secret
bob_shared = ecc.derive_shared_key(bob_priv, alice_pub)
print(f"Bob's shared secret: {bob_shared.hex()}")

# Verify that keys match
print(f"Keys match: {alice_shared == bob_shared}")