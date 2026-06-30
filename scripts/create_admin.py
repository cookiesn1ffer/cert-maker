#!/usr/bin/env python3
"""Interactive script to create or reset the admin account.

Run from the project root:
    python scripts/create_admin.py
"""
import os
import sys
import getpass

# Make sure project root is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dotenv import load_dotenv
load_dotenv()

from werkzeug.security import generate_password_hash
from models import create_admin_user, get_admin_by_username, get_admin_count, init_db, update_admin_password


def main():
    init_db()

    print("=== Cookie's Academy — Admin Account Setup ===\n")

    username = input("Username (default: admin): ").strip() or "admin"
    password = getpass.getpass("Password (min 8 chars): ")
    if len(password) < 8:
        print("Error: password must be at least 8 characters.")
        sys.exit(1)
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Error: passwords do not match.")
        sys.exit(1)

    pw_hash = generate_password_hash(password)
    existing = get_admin_by_username(username)

    if existing:
        overwrite = input(f"Username '{username}' already exists. Overwrite password? [y/N]: ").strip().lower()
        if overwrite != "y":
            print("Aborted.")
            sys.exit(0)
        update_admin_password(username, pw_hash)
        print(f"\nPassword updated for '{username}'.")
    else:
        create_admin_user(username, pw_hash)
        print(f"\nAdmin account '{username}' created successfully.")

    print("You can now log in at /login")


if __name__ == "__main__":
    main()
