#!/usr/bin/env python3

import subprocess
import platform
import re
import sys
import os
import shutil
import json
import itertools
import threading
import time
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
    \__ \( (__(___)( (__  )(__  _)(_ 
    (___/ \___)     \___)(____)(____)
    version v0.1
******************************************
"""

BINARY_EXTENSIONS = [
    ".exe", ".dll", ".so", ".bin", ".dat", ".class", ".pyc", ".o", ".a",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".mp3",
    ".mp4", ".avi", ".mov", ".mkv", ".pdf", ".doc", ".docx", ".ppt", ".pptx",
    ".xls", ".xlsx", ".zip", ".rar", ".tar", ".gz", ".7z", ".iso", ".jar"
]


def loading_animation(message="Processing..."):
    spinner = itertools.cycle(['-', '\\', '|', '/'])
    while not stop_loading_event.is_set():
        sys.stdout.write(f"\r{message} {next(spinner)}")
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write("\r" + " " * len(message) + "\r")  # Clear line when done


def has_binary_extension(file_path):
    _, ext = os.path.splitext(file_path)
    return ext.lower() in BINARY_EXTENSIONS


def is_binary_file(file_path):
    if has_binary_extension(file_path):
        return True

    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            if b'\0' in chunk:  # Binary files often contain null bytes
                return True
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return False
    return False


def check_for_wi_number(commit_message):
    match = re.search(r"[\n\r\t\s]*#[0-9]+|[\n\r\t\s]*#[A-Z]+-[0-9]+", commit_message)
    if match:
        return True
    else:
        print(f"{RED}")
        print(u"\U0001F980" + "  " + "ERROR: " + "Commit message is missing a #WI number.")
        print(f"{RESET}")
        return False


def get_staged_files():
    result = subprocess.run(
        ["git", "diff", "--name-only", "--cached"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    if result.returncode != 0:
        raise Exception(f"Error retrieving staged files: {result.stderr.strip()}")

    files = result.stdout.strip().split("\n")
    staged_files = [f for f in files if f]

    binary_files = [f for f in staged_files if is_binary_file(f)]
    if binary_files:
        print(f"{RED}*************************************************************************")
        print("INFO : The following binary files are staged for commit, which is not allowed:")
        for binary_file in binary_files:
            print(f" - {binary_file}")
        print(f"*************************************************************************{RESET}")
        sys.exit("ERROR : Commit aborted due to binary files in the staged changes.")

    return staged_files


def run_gitleaks():
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
            result = subprocess.run(
                [gitleaks_path, "detect", "--report-format", "json", "--report-path", report_path, "--no-git", "--source", file],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.getcwd()
            )
            if result.returncode != 0:
                print(u"\U0001F980" + "  " + f"{RED}WARNING : Gitleaks detected potential issues. Report saved to {report_path}.")
                print_issues_as_table(load_gitleaks_report(report_path))
                leaks_found = True
            else:
                print(f"INFO : No leaks detected by Gitleaks in the file: {file}")
        except Exception as e:
            print(f"Error running Gitleaks on {file}: {e}")

    return leaks_found


def encrypt_data(data, key):
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return (iv + ciphertext).hex()


def decrypt_data(encrypted_data, key):
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
    global stop_loading_event

    stop_loading_event = threading.Event()  # Event to stop the loading animation
    loading_thread = threading.Thread(target=loading_animation, args=("Committing...",))  # Spinner thread

    try:
        loading_thread.start()  # Start the spinner
        leaks_found = False

        if '--amend' in command and '-m' not in command:
            print("Amend editor mode is not supported. Please use the '-m' option with '--amend' to provide a commit message inline.")
            return

        if '-m' not in command and '--amend' not in command:
            raise ValueError("Error: You must provide a commit message using the '-m' option or use '--amend' to modify the previous commit.")

        if not is_repo_empty() and not has_staged_changes() and '--amend' in command:
            print("No staged changes detected, proceeding with commit message modification only.")
        else:
            leaks_found = run_gitleaks()

            if leaks_found and not confirm_false_positive():
                print(f"{RED}Aborting commit due to potential leaks.")
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

            for i, arg in enumerate(git_command):
                if arg == '-m' and i + 1 < len(git_command):
                    git_command[i + 1] = f"{git_command[i + 1]} | Enc: {encrypted_commit_id}"
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
            print(f"{RED}\nWARNING: Leaks were detected by Gitleaks. Commit has proceeded, but you should review and address the leaks.\n{RESET}")

    finally:
        stop_loading_event.set()  # Stop the spinner
        loading_thread.join()  # Wait for the spinner thread to finish


def run_git_push():
    global stop_loading_event

    stop_loading_event = threading.Event()  # Event to stop the loading animation
    loading_thread = threading.Thread(target=loading_animation, args=("Pushing...",))  # Spinner thread

    try:
        loading_thread.start()  # Start the spinner
        all_commits_with_issues = run_gitleaks_and_load_report()

        commits_since_last_push = get_commits_since_last_push()
        print(commits_since_last_push)

        if not commits_since_last_push:
            print("No commits found to push.")
            return

        recent_issues = compare_commits_with_issues(all_commits_with_issues, commits_since_last_push)

        if recent_issues and not confirm_proceed():
            print("Aborting push due to potential leaks in recent commits.")
            return

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

    finally:
        stop_loading_event.set()  # Stop the spinner
        loading_thread.join()  # Wait for the spinner thread to finish


def run_any_git_command(git_args):
    global stop_loading_event

    stop_loading_event = threading.Event()  # Event to stop the loading animation
    loading_thread = threading.Thread(target=loading_animation, args=("Running git command...",))  # Spinner thread

    try:
        loading_thread.start()  # Start the spinner
        result = subprocess.run(
            ['git'] + git_args,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.getcwd()
        )

        print("INFO: Done.")
        print(result.stdout.strip())

    finally:
        stop_loading_event.set()  # Stop the spinner
        loading_thread.join()  # Wait for the spinner thread to finish


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(product)
        print(f"{RESET}")
        print("Usage: gits <commit|verify|status|...> [args]")
        sys.exit(0)

    action = sys.argv[1]

    if action == "commit":
        run_git_commit(sys.argv[2:])
    elif action == "push":
        run_git_push()
    else:
        run_any_git_command(sys.argv[1:])
