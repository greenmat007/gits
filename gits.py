import subprocess
import re
import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding

# AES key for encryption/decryption (must match on both sides)
AES_KEY = b"6a09e667f3bcc908b5dbd2e358629012"  # 16-byte key for AES-128 encryption/decryption

# Function to encrypt data using AES
def encrypt_data(data, key):
    """
    Encrypt the data using AES encryption in CBC mode.
    :param data: The plaintext data to encrypt.
    :param key: The AES key for encryption (must be 16, 24, or 32 bytes).
    :return: Encrypted data (ciphertext) in hex format.
    """
    # Add padding to the plaintext to match AES block size (16 bytes)
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    # Initialize the AES cipher with the key and a random IV (Initialization Vector)
    iv = os.urandom(16)  # AES block size is 16 bytes
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Encode the IV and ciphertext in hex format for compact representation
    return (iv + ciphertext).hex()

# Function to decrypt data using AES
def decrypt_data(encrypted_data, key):
    """
    Decrypt the data using AES decryption in CBC mode.
    :param encrypted_data: The encrypted data in hex format.
    :param key: The AES key for decryption (must be 16, 24, or 32 bytes).
    :return: Decrypted data (plaintext).
    """
    # Decode the hex-encoded encrypted data
    encrypted_bytes = bytes.fromhex(encrypted_data)

    # Split the IV (first 16 bytes) and the ciphertext
    iv = encrypted_bytes[:16]
    ciphertext = encrypted_bytes[16:]

    # Initialize the AES cipher with the key and the extracted IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding from the plaintext
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext.decode('utf-8')

# Function to retrieve the latest commit ID using git log
def get_latest_commit_id():
    """
    Get the latest commit ID (the most recent commit) using git log.
    :return: Latest commit ID as a string.
    """
    result = subprocess.run(
        ["git", "log", "-1", "--format=%H"],
        text=True,
        capture_output=True,
        cwd=os.getcwd()  # Ensure that git commands run in the current working directory
    )
    if result.returncode != 0:
        raise Exception(f"Failed to retrieve latest commit ID using git log: {result.stderr.strip()}")

    latest_commit_id = result.stdout.strip()
    return latest_commit_id

# Function to retrieve the n-1 commit ID relative to a given commit ID
def get_n_minus_one_commit_id(commit_id):
    """
    Get the n-1 commit ID relative to a given commit ID using git log.
    :param commit_id: The ID of the commit from which to get the n-1 commit.
    :return: n-1 commit ID as a string.
    """
    result = subprocess.run(
        ["git", "log", "-2", "--format=%H", commit_id],
        text=True,
        capture_output=True,
        cwd=os.getcwd()  # Ensure that git commands run in the current working directory
    )
    if result.returncode != 0:
        raise Exception(f"Failed to retrieve n-1 commit ID relative to {commit_id}: {result.stderr.strip()}")

    # Get the second commit from the output (n-1 commit)
    commit_ids = result.stdout.strip().split("\n")
    if len(commit_ids) < 2:
        raise Exception("Not enough commits to get the n-1 commit.")

    n_minus_one_commit_id = commit_ids[1]
    return n_minus_one_commit_id

# Function to extract the encrypted data from the commit message
def extract_encrypted_data(commit_message):
    """
    Extract the encrypted portion from the commit message.
    :param commit_message: The commit message containing the encrypted data.
    :return: Encrypted data in hex format.
    """
    # Regex pattern to extract the encrypted part: "Enc: <hex-encoded encrypted data>"
    match = re.search(r"Enc:\s([a-fA-F0-9]+)", commit_message)
    
    if match:
        return match.group(1)
    else:
        print("No encrypted data found in the commit message.")
        return None

# Function to retrieve the commit message for a specific commit ID
def get_commit_message(commit_id):
    """
    Get the commit message for a specific Git commit.
    :param commit_id: The ID of the Git commit.
    :return: Commit message as a string.
    """
    result = subprocess.run(
        ["git", "log", "-1", "--format=%B", commit_id],
        text=True,
        capture_output=True
    )
    if result.returncode != 0:
        raise Exception(f"Failed to retrieve commit message for commit {commit_id}: {result.stderr.strip()}")
    
    commit_message = result.stdout.strip()
    return commit_message

# Function to verify the commit by decrypting the encrypted n-1 commit ID
def verify_commit_message(commit_id):
    """
    Verify the commit message by decrypting the encrypted n-1 commit ID and comparing it to the actual n-1 commit ID.
    :param commit_id: The commit ID to verify.
    """
    # Retrieve the commit message for the given commit ID
    commit_message = get_commit_message(commit_id)

    # Extract the encrypted portion of the commit message
    encrypted_data = extract_encrypted_data(commit_message)

    if encrypted_data:
        try:
            # Decrypt the encrypted n-1 commit ID
            decrypted_commit_id = decrypt_data(encrypted_data, AES_KEY)

            # Get the actual n-1 commit ID relative to the given commit
            n_minus_one_commit_id = get_n_minus_one_commit_id(commit_id)

            # Compare the decrypted commit ID with the actual n-1 commit ID
            if decrypted_commit_id == n_minus_one_commit_id:
                print("Commit message is valid.")
            else:
                print(f"Commit message is invalid.\nDecrypted commit ID: {decrypted_commit_id}\nActual n-1 commit ID: {n_minus_one_commit_id}")
        except Exception as e:
            print(f"Decryption failed: {e}")
    else:
        print("Failed to verify the commit message.")

# Function to run git command with encrypted latest commit ID for 'git commit'
def run_git_commit(command):
    """
    Run a git command for commit with the given options passed as a list of arguments.
    :param command: List of git options and arguments (e.g., ['commit', '-m', 'message']).
    """
    try:
        # Prepend 'git' to the command
        git_command = ['git','commit'] + command

        # Retrieve the latest commit ID using git log before committing
        latest_commit_id = get_latest_commit_id()

        # Encrypt the latest commit ID
        encrypted_commit_id = encrypt_data(latest_commit_id, AES_KEY)

        # Find and modify the commit message for the '-m' argument
        for i, arg in enumerate(git_command):
            if arg == '-m' and i + 1 < len(git_command):
                git_command[i + 1] = f"{git_command[i + 1]} | Enc: {encrypted_commit_id}"
                break

        # Run the git commit command with the updated commit message
        result = subprocess.run(
            git_command,            # Git command and arguments as a list
            text=True,              # Capture output as a string
            stdout=subprocess.PIPE,  # Capture standard output
            stderr=subprocess.PIPE,  # Capture standard error
            cwd=os.getcwd()          # Ensure that git commands run in the current working directory
        )
    

        # Print the output of the git commit command
        print(result.stdout.strip())

    except Exception as e:
        print(f"Error: {e}")

# Function to run any general git command
def run_any_git_command(git_args):
    """
    Run any git command by passing the arguments as is.
    :param git_args: The list of arguments for the git command.
    """
    try:
        result = subprocess.run(
            ['git'] + git_args,         # Git command with user-specified arguments
            text=True,                  # Capture output as text
            stdout=subprocess.PIPE,      # Capture standard output
            stderr=subprocess.PIPE,      # Capture standard error
            cwd=os.getcwd()              # Ensure that git commands run in the current working directory
        )


        # Print the output of the git command
        print(result.stdout.strip())

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <commit|verify| [git args]")
        sys.exit(1)

    action = sys.argv[1]

    if action == "commit":
        # For commit command
        run_git_commit(sys.argv[2:])
    elif action == "verify":
        # For verification command
        if len(sys.argv) != 3:
            print("Usage: python script.py verify <commit_id>")
            sys.exit(1)
        commit_id = sys.argv[2]
        verify_commit_message(commit_id)
    else:
        run_any_git_command(sys.argv[1:])

