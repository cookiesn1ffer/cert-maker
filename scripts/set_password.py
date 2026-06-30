#!/usr/bin/env python3
"""
Usage: python scripts/set_password.py <password>

Prints a bcrypt hash to paste into .env as ADMIN_PASSWORD_HASH.
"""
import sys

def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/set_password.py <password>", file=sys.stderr)
        sys.exit(1)

    password = sys.argv[1]
    try:
        from werkzeug.security import generate_password_hash
    except ImportError:
        print("werkzeug not installed. Run: pip install werkzeug", file=sys.stderr)
        sys.exit(1)

    h = generate_password_hash(password, method="pbkdf2:sha256")
    print(f"\nADMIN_PASSWORD_HASH={h}\n")
    print("Paste the line above into your .env file.", file=sys.stderr)

if __name__ == "__main__":
    main()
