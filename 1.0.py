#!/usr/bin/env python3

import subprocess
import platform
import re
import sys
import os
import shutil
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from prettytable import PrettyTable


def derive_aes_key_from_commit_id(commit_id):
    """
    Generate an AES key from the first 32 characters of the commit ID.
    :param commit_id: The commit ID (SHA-1 hash, typically 40 characters).
    :return: A 16-byte AES-128 key derived from the commit ID.
    """
    # Take the first 32 characters from the commit ID and convert them to bytes
    commit_id_bytes = commit_id[:32].encode('utf-8')
    return commit_id_bytes[:16]  # Return the first 16 bytes for AES-128

BLUE = "\033[94m"
RESET = "\033[0m" 
product = f"""
    {BLUE} "'  //}}
    ( ''"
    _||__ ____ ____ ____  
    (o)___)}}___}}___}}___}}
    'U'0 0  0 0  0 0  0 0{RESET}
    """

def find_gitleaks():
    """
    Check if Gitleaks is installed and available in the system's path.
    If not found, prompt the user for the Gitleaks location.
    :return: The path to the Gitleaks executable.
    """
    gitleaks_path = shutil.which("gitleaks")
    if gitleaks_path:
        return gitleaks_path
    else:
        print("Gitleaks was not found in the system's PATH. Please add in the PATH to proceed")
        sys.exit(1)

# Function to check for #WI number in the commit message
def check_for_wi_number(commit_message):
    """
    Check if the commit message contains a #WI followed by a number.
    :param commit_message: The commit message to check.
    :return: True if the #WI number is present, False otherwise.
    """
    match = re.search(r"#WI\d+", commit_message)
    if match:
        return True
    else:
        print("Commit message is missing a #WI number.")
        return False

# Function to get the list of staged files
def get_staged_files():
    """
    Get the list of staged files using `git diff --name-only --cached`.
    :return: A list of staged file paths.
    """
    result = subprocess.run(
        ["git", "diff", "--name-only", "--cached"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    if result.returncode != 0:
        raise Exception(f"Error retrieving staged files: {result.stderr.strip()}")
    
    files = result.stdout.strip().split("\n")
    return [f for f in files if f]  # Filter out any empty strings

# Function to run Gitleaks before committing
def run_gitleaks():
    """
    Run Gitleaks programmatically before the Git commit and provide a warning if leaks are present.
    :return: True if leaks are found, False otherwise.
    """
    gitleaks_path = find_gitleaks()
    staged_files = get_staged_files()
    report_path = "../gl.json"

    if not staged_files:
        print("No files are staged for commit.")
        sys.exit(1)

    leaks_found = False

    for file in staged_files:
        try:
            # Run Gitleaks on each individual file
            result = subprocess.run(
                [gitleaks_path, "detect", "--report-format", "json", "--report-path", report_path, "--no-git", "--source", file],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.getcwd()
            )
            if result.returncode != 0:
                print(f"Gitleaks detected potential issues. Report saved to {report_path}.")
                print_issues_as_table(load_gitleaks_report(report_path))  # Print the issues in a table format
                leaks_found = True
            else:
                print(f"No leaks detected by Gitleaks in the file: {file}")
        except Exception as e:
            print(f"Error running Gitleaks on {file}: {e}")

    return leaks_found

# Function to encrypt data using AES
def encrypt_data(data, key):
    """
    Encrypt the data using AES encryption in CBC mode.
    :param data: The plaintext data to encrypt.
    :param key: The AES key for encryption (must be 16, 24, or 32 bytes).
    :return: Encrypted data (ciphertext) in hex format.
    """
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    iv = os.urandom(16)  # AES block size is 16 bytes
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return (iv + ciphertext).hex()

# Function to decrypt data using AES
def decrypt_data(encrypted_data, key):
    """
    Decrypt the data using AES decryption in CBC mode.
    :param encrypted_data: The encrypted data in hex format.
    :param key: The AES key for decryption (must be 16, 24, or 32 bytes).
    :return: Decrypted data (plaintext).
    """
    encrypted_bytes = bytes.fromhex(encrypted_data)
    iv = encrypted_bytes[:16]
    ciphertext = encrypted_bytes[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext.decode('utf-8')

def is_repo_empty():
    """
    Check if the repository is empty (i.e., has no commits).
    :return: True if the repository is empty, False otherwise.
    """
    result = subprocess.run(
        ["git", "rev-list", "--count", "HEAD"],
        text=True,
        capture_output=True,
        cwd=os.getcwd()
    )
    if result.returncode != 0:
        return True if "unknown revision or path" in result.stderr else False
    return int(result.stdout.strip()) == 0

def get_latest_commit_id():
    """
    Get the latest commit ID (the most recent commit) using git log.
    :return: Latest commit ID as a string, or None if the repository is empty.
    """
    if is_repo_empty():
        print("The repository has no commits.")
        return None

    result = subprocess.run(
        ["git", "log", "-1", "--format=%H"],
        text=True,
        capture_output=True,
        cwd=os.getcwd()
    )
    if result.returncode != 0:
        raise Exception(f"Failed to retrieve latest commit ID: {result.stderr.strip()}")

    return result.stdout.strip()

def run_git_commit(command):
    """
    Run a git command for commit with the given options passed as a list of arguments.
    :param command: List of git options and arguments (e.g., ['commit', '-m', 'message'] or ['commit', '--amend']).
    """
    leaks_found = False
    try:
        if '--amend' in command and '-m' not in command:
            print("Amend editor mode is not supported. Please use the '-m' option with '--amend' to provide a commit message inline.")
            return

        if '-m' not in command and '--amend' not in command:
            raise ValueError("Error: You must provide a commit message using the '-m' option or use '--amend' to modify the previous commit.")

        if not is_repo_empty() and not has_staged_changes() and '--amend' in command:
            print("No staged changes detected, proceeding with commit message modification only.")
        else:
            leaks_found = run_gitleaks()
            if leaks_found:
                if not confirm_false_positive():
                    print("Aborting commit due to potential leaks.")
                    return

        git_command = ['git', 'commit'] + command

        if is_repo_empty():
            print("This is the first commit. Skipping commit message modification.")
            result = subprocess.run(
                git_command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.getcwd()
            )
            if result.returncode != 0:
                raise Exception(f"Git commit command failed: {result.stderr.strip()}")
            print(result.stdout.strip())
            return

        if '-m' in command:
            for i, arg in enumerate(git_command):
                if arg == '-m' and i + 1 < len(git_command):
                    commit_message = git_command[i + 1]
                    if not check_for_wi_number(commit_message):
                        print("Aborting commit due to missing #WI number.")
                        return
                    
                    latest_commit_id = get_latest_commit_id()
                    if not latest_commit_id:
                        print("Cannot retrieve latest commit ID.")
                        return

                    aes_key = derive_aes_key_from_commit_id(latest_commit_id)
                    encrypted_commit_id = encrypt_data(latest_commit_id, aes_key)

                    git_command[i + 1] = f"{commit_message} | Enc: {encrypted_commit_id}"
                    break

            result = subprocess.run(
                git_command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.getcwd()
            )
            if result.returncode != 0:
                raise Exception(f"Git commit command failed: {result.stderr.strip()}")
            print(result.stdout.strip())

        if leaks_found:
            print("\nWARNING: Leaks were detected by Gitleaks. Commit has proceeded, but you should review and address the leaks.")

    except Exception as e:
        print(f"Error: {e}")

def has_staged_changes():
    """
    Check if there are any staged changes in the current repository.
    :return: True if there are staged changes, False otherwise.
    """
    result = subprocess.run(
        ['git', 'diff', '--cached', '--name-only'],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=os.getcwd()
    )
    if result.returncode != 0:
        raise Exception(f"Failed to check for staged changes: {result.stderr.strip()}")

    return bool(result.stdout.strip())

# Function to extract the encrypted data from the commit message
def extract_encrypted_data(commit_message):
    """
    Extract the encrypted portion from the commit message.
    :param commit_message: The commit message containing the encrypted data.
    :return: Encrypted data in hex format.
    """
    match = re.search(r"Enc:\s([a-fA-F0-9]+)", commit_message)
    if match:
        return match.group(1)
    else:
        print("No encrypted data found in the commit message.")
        return None

def confirm_false_positive():
    """
    Prompt the user to confirm that the detected leaks are false positives.
    :return: True if the user confirms they are false positives, False otherwise.
    """
    while True:
        response = input("Do you confirm that these leaks are false positives? (yes/no): ").strip().lower()
        if response == "yes":
            return True
        elif response == "no":
            return False
        else:
            print("Invalid input. Please type 'yes' or 'no'.")

def print_issues_as_table(issues):
    """
    Print the issues in a table format using PrettyTable.
    :param issues: List of issues (leaks) from the Gitleaks report.
    """
    if not issues:
        print("No issues to display.")
        return

    table = PrettyTable()
    table.field_names = ["StartLine", "Commit", "Secret", "File"]

    for issue in issues:
        table.add_row([
            issue.get("StartLine", "N/A"),
            issue.get("Commit", "N/A"),
            issue.get("Secret", "N/A"),
            issue.get("File", "N/A"),
        ])    
        
    print(table)

# Main entry point
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(product)
        print(f"{BLUE}gits{RESET} {BLUE}version{RESET} {BLUE}v5.3{RESET}")
        print("Usage: gits <commit|verify|status|...> [args]")
        sys.exit(0)

    action = sys.argv[1]

    if action == "commit":
        run_git_commit(sys.argv[2:])
    else:
        print(f"Unknown action: {action}")
