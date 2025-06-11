"""
Password Generation Demo

Demonstrates secure password generation.
"""

from crypto_tools.passwords import generate_password

def main():
    print("=== Password Generation ===")
    
    # Default password
    password = generate_password()
    print(f"Default password (12 chars): {password}")
    
    # Longer password with special chars
    password = generate_password(length=16, use_special_chars=True)
    print(f"16-char password with special chars: {password}")
    
    # Password without special chars
    password = generate_password(length=14, use_special_chars=False)
    print(f"14-char password without special chars: {password}")
    
    # Generate multiple passwords
    print("\n=== Multiple Passwords ===")
    for i in range(3):
        print(f"Password {i+1}: {generate_password()}")

if __name__ == "__main__":
    main()