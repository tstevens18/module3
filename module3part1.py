"""
Module for computing SHA-256 hashes of strings and files.
"""

import hashlib

def hash_string(text):
    """
    Compute the SHA-256 hash of a given string.

    Args:
        text (str): The input string to hash.

    Returns:
        str: The hexadecimal representation of the SHA-256 hash.
    """
    return hashlib.sha256(text.encode()).hexdigest()

def hash_file(filename):
    """
    Compute the SHA-256 hash of a file's contents.

    Args:
        filename (str): The path to the file to hash.

    Returns:
        str: The hexadecimal representation of the SHA-256 hash.
    """
    sha256 = hashlib.sha256()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def main():
    """
    Main function to run the command-line interface for hashing strings or files.
    """
    print("1. Hash a string")
    print("2. Hash a file")
    choice = input("Choose an option (1/2): ")

    if choice == "1":
        text = input("Enter text: ")
        print("SHA-256:", hash_string(text))
    elif choice == "2":
        filename = input("Enter file path: ")
        try:
            print("SHA-256:", hash_file(filename))
        except FileNotFoundError:
            print("Error: File not found.")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
