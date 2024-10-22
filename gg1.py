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


BLUE = "\033[95m"
RESET = "\033[0m"
ITALIC = "\033[3m"
RED = "\033[91m"

product = f"""
 {BLUE} 
 ******************************************
     ___   ___       ___  __    ____ 
    / __) / __)___  / __)(  )  (_  _)
    \\__ \\( (__(___)( (__  )(__  _)(_ 
    (___/ \\___)     \\___)(____)(____)
    version v0.1
******************************************
"""


def find_gitleaks():
    gitleaks_path = shutil.which("gitleaks")
    if gitleaks_path:
        return gitleaks_path
    else:
        print("Gitleaks was not found in the system's PATH.")
        print("Please add gitleaks to your Windows PATH to proceed.")
        print("You can download gitleaks from: https://artifactory.global.standardchartered.com/artifactory/technology-standard-release/security/application-security/gitleaks/8.18.0/gitleaks_8.18.0_windows_armv6.zip")
        sys.exit(1)

# List of common binary file extensions
BINARY_EXTENSIONS = [
    ".exe", ".dll", ".so", ".bin", ".dat", ".class", ".pyc", ".o", ".a",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".mp3",
    ".mp4", ".avi", ".mov", ".mkv", ".pdf", ".doc", ".docx", ".ppt", ".pptx",
    ".xls", ".xlsx", ".zip", ".rar", ".tar", ".gz", ".7z", ".iso", ".jar"
]

def has_binary_extension(file_path):
    _, ext = os.path.splitext(file_path)
    return ext.lower() in BINARY_EXTENSIONS

def is_binary_file(file_path):
    # First check the extension
    if has_binary_extension(file_path):
        return True

    # If the extension is not a known binary type, check the content
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            if b'\0' in chunk: # Binary files often contain null bytes
                return True
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return False
    return False

# Function to check for #WI number in the commit message
def check_for_wi_number(commit_message):
    """
    Check if the commit message contains a #WI followed by a number.
    """
    match = re.search(r"[\n\r\t\s]*#[0-9]+|[\n\r\t\s]*#[A-Z]+-[0-9]+", commit_message)
    if match:
        return True
    else:
        print(f"{RED}")
        print(u"\U0001F980"+"  "+"ERROR: "+"Commit message is missing a #WI number.")
        print(f"{RESET}")
        return False


# Function to get the list of staged files and check for binary files
def get_staged_files():
    """
    Get the list of staged files using `git diff --name-only --cached`.
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
    staged_files = [f for f in files if f] # Filter out any empty strings

    # Check for binary files in the staged files
    binary_files = [f for f in staged_files if is_binary_file(f)]
    if binary_files:
        print(f"{RED}*************************************************************************")
        print("INFO : The following binary files are staged for commit, which is not allowed:")
        for binary_file in binary_files:
            print(f" - {binary_file}")
        print(f"*************************************************************************{RESET}")
        sys.exit("ERROR : Commit aborted due to binary files in the staged changes.")
    
    return staged_files # Only return non-binary files
   

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
        print("INFO : No files are staged for commit.")
        print(" ")
        sys.exit(1)

    leaks_found = False
    


    for file in staged_files:
        try:
            # Run Gitleaks on each individual file
            result = subprocess.run(
                [gitleaks_path, "detect", "--report-format", "json", "--report-path", report_path,"--no-git", "--source", file],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.getcwd()
            )
            if result.returncode != 0:
                print(u"\U0001F980"+"  "+"WARNING : "+f"{RED}Gitleaks detected potential issues. Report saved to {report_path}.")
                print_issues_as_table(load_gitleaks_report(report_path))  # Print the issues in a table format
                leaks_found = True
            else:
                print("INFO : "+f"No leaks detected by Gitleaks in the file: {file}")
        except Exception as e:
            print(f"Error running Gityleaks on {file}: {e}")

    return leaks_found

# Function to encrypt data using AES
def encrypt_data(data, key):
    """
    Encrypt the data using AES encryption in CBC mode.
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

# Function to check if the repository is empty (has no commits)
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
        # Handle cases where the repository has no commits
        return True if "unknown revision or path" in result.stderr else False
    return int(result.stdout.strip()) == 0

# Function to get the latest commit ID if available
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

# Function to retrieve the n-1 commit ID relative to a given commit ID
def get_n_minus_one_commit_id(commit_id):
    """
    Get the n-1 commit ID relative to a given commit ID using git log.
    """
    result = subprocess.run(
        ["git", "log", "-2", "--format=%H", commit_id],
        text=True,
        capture_output=True,
        cwd=os.getcwd()
    )
    if result.returncode != 0:
        raise Exception(f"Failed to retrieve n-1 commit ID relative to {commit_id}: {result.stderr.strip()}")

    commit_ids = result.stdout.strip().split("\n")
    if len(commit_ids) < 2:
        raise Exception("Not enough commits to get the n-1 commit.")

    return commit_ids[1]

def verify_commit_message(commit_id):
    """
    Verify the commit message by decrypting the encrypted commit ID
    """
    if is_repo_empty():
        print("The repository has no commits. No verification needed.")
        return

    # Retrieve the commit message for the given commit ID
    commit_message = get_commit_message(commit_id)

    # Extract the encrypted commit ID from the commit message
    encrypted_data = extract_encrypted_data(commit_message)
    if not encrypted_data:
        print("No encrypted data found in the commit message.")
        return

    # Get the n-1 commit ID (the one before the current commit ID)
    n_minus_one_commit_id = get_n_minus_one_commit_id(commit_id)

    # Dynamically derive the AES key from the n-1 commit ID
    aes_key = derive_aes_key_from_commit_id(n_minus_one_commit_id)

    try:
        # Decrypt the encrypted commit ID using the derived AES key
        decrypted_commit_id = decrypt_data(encrypted_data, aes_key)

        # Compare the decrypted commit ID with the actual n-1 commit ID
        if decrypted_commit_id == n_minus_one_commit_id:
            print("Commit message is valid.")
        else:
            print(f"Commit message is invalid.\nDecrypted commit ID: {decrypted_commit_id}\nActual n-1 commit ID: {n_minus_one_commit_id}")

    except Exception as e:
        print(f"Decryption failed: {e}")




# Function to ask for confirmation that leaks are false positives
def confirm_false_positive():
    """
    Prompt the user to confirm that the detected leaks are false positives.
    """
    while True:
        response = input("Do you confirm that these leaks are false positives? (yes/no): ").strip().lower()
        if response == "yes":
            return True
        elif response == "no":
            return False
        else:
            print("Invalid input. Please type 'yes' or 'no'.")

def run_git_commit(command):
    """
    Run a git command for commit with the given options passed as a list of arguments.
    """
    print(product)
    print(f"{RESET}")
    leaks_found=False
    try:
        # Detect if '--amend' is used without '-m'
        if '--amend' in command and '-m' not in command:
            print("Amend editor mode is not supported. Please use the '-m' option with '--amend' to provide a commit message inline.")
            return

        # If neither -m nor --amend was provided, throw an error early
        if '-m' not in command and '--amend' not in command:
            raise ValueError("Error: You must provide a commit message using the '-m' option or use '--amend' to modify the previous commit.")

        # Run Gitleaks if there are staged files, otherwise skip the check
        if not is_repo_empty() and not has_staged_changes() and  '--amend'  in command:
            print("No staged changes detected, proceeding with commit message modification only.")
        else:
            leaks_found = run_gitleaks()

            # If leaks are found, ask for confirmation
            if leaks_found:
                if not confirm_false_positive():
                    print(f"{RED}Aborting commit due to potential leaks.")
                    print(f"{RESET}")
                    return

        git_command = ['git', 'commit'] + command

        # Check if the repository is empty, skip commit message modification if it is
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

        # Handle the case where '-m' is provided (including with --amend)
        if '-m' in command:
            for i, arg in enumerate(git_command):
                if arg == '-m' and i + 1 < len(git_command):
                    commit_message = git_command[i + 1]
                    if not check_for_wi_number(commit_message):
                        print("Aborting commit due to missing #WI number.")
                        return
            
            # Get the latest commit ID before proceeding
            latest_commit_id = get_latest_commit_id()
            if not latest_commit_id:
                print("Cannot retrieve latest commit ID.")
                return

            # Dynamically generate the AES key from the latest commit ID
            aes_key = derive_aes_key_from_commit_id(latest_commit_id)

            # Encrypt the latest commit ID using the derived AES key
            encrypted_commit_id = encrypt_data(latest_commit_id, aes_key)

            # Modify the commit message inline (when using -m)
            for i, arg in enumerate(git_command):
                if arg == '-m' and i + 1 < len(git_command):
                    git_command[i + 1] = f"{git_command[i + 1]} | Enc: {encrypted_commit_id}"
                    break
            print(product)
            print(f"{RESET}")
            # Run the git commit command with the updated message
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

        # Inform the user about leaks after committing
        if leaks_found:
            print(f"{RED}\nWARNING: Leaks were detected by Gitleaks. Commit has proceeded, but you should review and address the leaks.\n{RESET}")


    except Exception as e:
        print(f"Error: {e}")


def has_staged_changes():
    """
    Check if there are any staged changes in the current repository.
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

# Function to retrieve the commit message for a specific commit ID
def get_commit_message(commit_id):
    """
    Get the commit message for a specific Git commit.
    """
    result = subprocess.run(
        ["git", "log", "-1", "--format=%B", commit_id],
        text=True,
        capture_output=True
    )
    if result.returncode != 0:
        raise Exception(f"Failed to retrieve commit message for commit {commit_id}: {result.stderr.strip()}")

    return result.stdout.strip()

# Function to run any general git command
def run_any_git_command(git_args):
    """
    Run any git command by passing the arguments as is.
    """
    print(product)
    print(f"{RESET}")
    # ANSI escape sequences for colors
    try:
        result = subprocess.run(
            ['git'] + git_args,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.getcwd()
        )

        print("INFO: Done.")
        print(result.stdout.strip())
        print(result.stderr)

    except Exception as e:
        print(f"Error: {e}")
        print(result.stdout.strip())

# Push


def get_commits_since_last_push():
    """
    Get the list of commits made since the last push to the current branch.
    :return: A list of commit hashes.
    """
    try:
        # Get the current branch name
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.getcwd()
        )
        branch_name = result.stdout.strip()

        # Get the list of commits since the last push
        result = subprocess.run(
            ["git", "log", f"origin/{branch_name}..HEAD", "--format=%H"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.getcwd()
        )
        if result.returncode != 0:
            raise Exception(f"Failed to get commits since last push: {result.stderr.strip()}")

        commits = result.stdout.strip().split("\n")
        return commits if commits != [''] else []  # Return an empty list if no commits found
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def run_gitleaks_and_load_report():
    """
    Run Gitleaks on all commits and save the report to gl.json.
    Then load the JSON report from the file and return the commit hashes with issues.
    :return: A list of commit hashes where leaks were found.
    """
    try:
        gitleaks_path = find_gitleaks()
        report_path = "../gl.json"
        
        # Run Gitleaks and generate the JSON report
        print(f"INFO : Running Gitleaks  and saving report to {report_path}...")
        result = subprocess.run(
            [gitleaks_path, "detect", "--report-format", "json", "--report-path", report_path],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.getcwd()
        )
        # if result.returncode != 0:
            # print(f"Gitleaks detected potential issues. Report saved to {report_path}.")
        
        # Load the JSON report from the file
        return load_gitleaks_report(report_path)

    except Exception as e:
        print(f"Error running Gitleaks and loading report: {e}")
        return []


def load_gitleaks_report(report_path):
    """
    Load the Gitleaks report from the JSON file and return all the entries.
    """
    try:
        with open(report_path, 'r') as file:
            leaks = json.load(file)
        return leaks  # Return all the entries from the report
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading or parsing Gitleaks report: {e}")
        return []  # Return empty list if report cannot be loaded or parsed


def print_issues_as_table(issues):
    """
    Print the issues in a table format using PrettyTable.
    :param issues: List of issues (leaks) from the Gitleaks report.
    """
    if not issues:
        print("INFO: No issues to display.")
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
    print(f"{RED}")
    print(table)
    print(f"{RESET}")


def confirm_proceed():
    """
    Ask the user if they want to proceed with the push despite potential leaks.
    :return: True if the user confirms, False otherwise.
    """
    while True:
        response = input("Leaks were detected in recent commits. Do you want to proceed with the push? (yes/no): ").strip().lower()
        if response == "yes":
            return True
        elif response == "no":
            return False
        else:
            print("Invalid response. Please type 'yes' or 'no'.")


def compare_commits_with_issues(commits_with_issues, commits_since_last_push):
    """
    Compare the commits with issues detected by Gitleaks against the commits made since the last push.
    """
    issues_in_recent_commits = [issue for issue in commits_with_issues if issue.get("Commit") in commits_since_last_push]
    if issues_in_recent_commits:
        print(u"\U0001F980"+"  "+"WARNING : "+f"{RED}Gitleaks detected potential issues in the following recent commits:")
        print_issues_as_table(issues_in_recent_commits)  # Print the issues in a table format
    else:
        print(f"INFO : Gitleaks No issues found")
    return issues_in_recent_commits


def run_git_push():
    """
    Run the git push command, but first run Gitleaks on all commits and compare against the commits since the last push.
    If leaks are found in the recent commits, ask the user if they want to proceed with the push.
    """
    try:
        # Run Gitleaks and load the report
        all_commits_with_issues = run_gitleaks_and_load_report()

        # Get the commits since the last push
        commits_since_last_push = get_commits_since_last_push()
        print(commits_since_last_push)

        # If no commits are found since the last push, exit
        if not commits_since_last_push:
            print("No commits found to push.")
            return

        # Compare the commits with issues against the commits made since the last push
        recent_issues = compare_commits_with_issues(all_commits_with_issues, commits_since_last_push)

        # If issues are found in recent commits, ask for confirmation
        if recent_issues:
            if not confirm_proceed():
                print("Aborting push due to potential leaks in recent commits.")
                return
        print(product)
        print(f"{RESET}")
        # If no leaks or user confirmed, proceed with push
        result = subprocess.run(
            ["git", "push"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.getcwd()
        )
        if result.returncode != 0:
            raise Exception(f"Git push command failed: {result.stderr.strip()}")
        print(result.stdout.strip())
        print(result.stderr)
    except Exception as e:
        print(f"Error: {e}")


"""
Run the git main Program
"""

if __name__ == "__main__":
 
    if len(sys.argv) < 2:
        print(product)  # Display product information with banner
        print(f"{RESET}")
        print("Welcome to the GITS CLI Tool!")
        print("=========================================")
        print("A utility for performing Git operations with")
        print("additional security checks and automated tasks.")
        print("")
        print(f"{ITALIC}Usage:{RESET}")
        print("  gits <command> [args]")
        print("")
        print(f"{ITALIC}Available Commands:{RESET}")
        print("  commit      Commit changes with security checks")
        print("  verify      Verify commit integrity with commit ID")
        print("  push        Push changes to the repository with checks")
        print("  status      Show the current status of the Git repository")
        print("")
        print(f"{RED}Example usage:{RESET}")
        print("  gits commit -m 'Your commit message'  # Commit with a message")
        print("  gits verify <commit_id>               # Verify a commit")
        print("")
        print("For more details on each command, run 'gits <command> --help'")
        sys.exit(0)



    action = sys.argv[1]

    if action == "commit":
        run_git_commit(sys.argv[2:])
    elif action == "verify":
        if len(sys.argv) != 3:
            print("Usage: python script.py verify <commit_id>")
            sys.exit(0)
        commit_id = sys.argv[2]
        verify_commit_message(commit_id)
    elif action == "push":
        run_git_push() 
    else:
        run_any_git_command(sys.argv[1:])
        