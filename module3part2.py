"""
Module for implementing the Caesar cipher encryption and decryption.
"""

def caesar_cipher(text, shift, mode):
    """
    Encrypt or decrypt text using the Caesar cipher.

    Args:
        text (str): The input text to process.
        shift (int): The number of positions to shift the letters.
        mode (str): Either 'encrypt' or 'decrypt'.

    Returns:
        str: The processed text.
    """
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            if mode == "encrypt":
                result += chr((ord(char) - base + shift) % 26 + base)
            elif mode == "decrypt":
                result += chr((ord(char) - base - shift) % 26 + base)
        else:
            result += char  # Non-letters are unchanged
    return result


def main():
    """
    Main function to run the command-line interface for Caesar cipher.
    """
    print("=== Caesar Cipher App ===")
    mode = input("Type 'encrypt' or 'decrypt': ").strip().lower()

    if mode not in ["encrypt", "decrypt"]:
        print("Invalid option.")
        return

    text = input("Enter your message: ")
    try:
        shift = int(input("Enter shift number (e.g., 3): "))
    except ValueError:
        print("Shift must be a number.")
        return

    result = caesar_cipher(text, shift, mode)
    print(f"\nResult ({mode}ed text): {result}")


if __name__ == "__main__":
    main()
