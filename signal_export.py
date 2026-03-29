#!/usr/bin/env python3
"""
signal_export.py — Export Signal Desktop messages on macOS.

Handles Signal Desktop >= 7.x where the SQLCipher key is protected
via Electron safeStorage (macOS Keychain + PBKDF2), replacing the
pre-2024 plaintext key in config.json.

Usage:
    python3 signal_export.py                        # print PRAGMA key only
    python3 signal_export.py --export messages.csv  # export all messages to CSV
    python3 signal_export.py --export messages.json # export all messages to JSON
    python3 signal_export.py --conversation "Alice" --export alice.csv
    python3 signal_export.py --after 2024-01-01 --export recent.csv
    python3 signal_export.py --list-conversations    # list all conversations

Requirements:
    pip install cryptography

Signal must be closed before running.
"""

import argparse
import csv
import ctypes
import ctypes.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SIGNAL_DIR = Path.home() / "Library/Application Support/Signal"
CONFIG_PATH = SIGNAL_DIR / "config.json"
DB_PATH = SIGNAL_DIR / "sql/db.sqlite"


# --- Keychain ---

def get_keychain_password():
    security = ctypes.cdll.LoadLibrary(ctypes.util.find_library("Security"))
    password_data = ctypes.c_void_p()
    password_length = ctypes.c_uint32()
    service = b"Signal Safe Storage"

    for account in (b"Signal Key", None):
        result = security.SecKeychainFindGenericPassword(
            None,
            len(service), service,
            len(account) if account else 0, account,
            ctypes.byref(password_length),
            ctypes.byref(password_data),
            None,
        )
        if result == 0:
            break

    if result != 0:
        print("ERROR: Could not read from Keychain (code {}).".format(result))
        print("Make sure Terminal has Keychain access and Signal is closed.")
        sys.exit(1)

    key_bytes = ctypes.string_at(password_data, password_length.value)
    security.SecKeychainItemFreeContent(None, password_data)
    return key_bytes


# --- Key derivation ---

def derive_sqlcipher_key(config_path=CONFIG_PATH):
    with open(config_path) as f:
        config = json.load(f)

    encrypted_key = config.get("encryptedKey") or config.get("key")
    if not encrypted_key:
        print("ERROR: No key found in config.json. Fields: " + str(list(config.keys())))
        sys.exit(1)

    # Pre-2024 Signal stored a plaintext hex key directly
    if not encrypted_key.startswith("76") and len(encrypted_key) == 64:
        print("Detected legacy plaintext key.")
        return encrypted_key

    keychain_password = get_keychain_password()

    # Chromium OSCrypt: PBKDF2-SHA1, raw password (no base64 decode),
    # salt=saltysalt, 1003 iterations, 16 bytes -> AES-128-CBC, IV=16 spaces
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        print("ERROR: Missing dependency. Run: pip install cryptography")
        sys.exit(1)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=16,
        salt=b"saltysalt",
        iterations=1003,
        backend=default_backend(),
    )
    aes_key = kdf.derive(keychain_password)

    encrypted = bytes.fromhex(encrypted_key)
    prefix = encrypted[:3]
    if prefix not in (b"v10", b"v11"):
        print("WARNING: Unexpected prefix: " + repr(prefix) + " — attempting anyway.")

    iv = b" " * 16
    ciphertext = encrypted[3:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    pad_len = plaintext[-1]
    if 1 <= pad_len <= 16:
        plaintext = plaintext[:-pad_len]

    return plaintext.decode("utf-8")


# --- Database access via sqlcipher CLI ---

def check_sqlcipher():
    if not shutil.which("sqlcipher"):
        print("ERROR: sqlcipher not found. Run: brew install sqlcipher")
        sys.exit(1)


def run_sqlcipher(key, sql, db_path=DB_PATH):
    check_sqlcipher()
    tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
    tmp.close()
    try:
        shutil.copy2(db_path, tmp.name)
        cmd = "PRAGMA key = \"x'{key}'\"; {sql}".format(key=key, sql=sql)
        result = subprocess.run(
            ["sqlcipher", "-list", "-noheader", tmp.name],
            input=cmd,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0 or "Parse error" in result.stderr:
            print("ERROR: sqlcipher failed.")
            print(result.stderr)
            sys.exit(1)
        return result.stdout
    finally:
        os.unlink(tmp.name)


# --- Conversation helpers ---

def list_conversations(key):
    sql = "SELECT id, json FROM conversations ORDER BY active_at DESC NULLS LAST;"
    output = run_sqlcipher(key, sql)
    conversations = []
    for line in output.strip().splitlines():
        parts = line.split("|", 1)
        if len(parts) == 2:
            try:
                data = json.loads(parts[1])
                name = (
                    data.get("name")
                    or data.get("profileName")
                    or data.get("e164")
                    or data.get("groupId")
                    or parts[0]
                )
                conversations.append({"id": parts[0], "name": name})
            except json.JSONDecodeError:
                pass
    return conversations


def find_conversation_id(key, name_fragment):
    convos = list_conversations(key)
    matches = [c for c in convos if name_fragment.lower() in c["name"].lower()]
    if not matches:
        print("No conversation matching: " + name_fragment)
        print("Available conversations:")
        for c in convos:
            print("  " + c["name"])
        sys.exit(1)
    if len(matches) > 1:
        print("Multiple matches:")
        for c in matches:
            print("  " + c["name"])
        print("Please be more specific.")
        sys.exit(1)
    return matches[0]["id"]


# --- Export ---

def build_message_sql(conversation_id=None, after=None):
    conditions = []
    if conversation_id:
        conditions.append("conversationId = '{}'".format(conversation_id))
    if after:
        # Signal stores timestamps as milliseconds
        import datetime
        dt = datetime.datetime.strptime(after, "%Y-%m-%d")
        ms = int(dt.timestamp() * 1000)
        conditions.append("sent_at >= {}".format(ms))
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    return "SELECT json FROM messages {} ORDER BY sent_at ASC;".format(where)


def export_messages(key, output_path, conversation_id=None, after=None):
    sql = build_message_sql(conversation_id, after)
    raw = run_sqlcipher(key, sql)
    lines = [l for l in raw.strip().splitlines() if l.strip()]

    records = []
    for line in lines:
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            pass

    ext = Path(output_path).suffix.lower()

    if ext == ".json":
        with open(output_path, "w") as f:
            json.dump(records, f, indent=2)
    else:
        # CSV: flatten the most useful fields
        fields = ["sent_at", "type", "body", "conversationId", "source", "hasAttachments", "id"]
        with open(output_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for r in records:
                # Convert timestamp to ISO
                if "sent_at" in r:
                    import datetime
                    r["sent_at"] = datetime.datetime.fromtimestamp(
                        r["sent_at"] / 1000
                    ).isoformat()
                writer.writerow({k: r.get(k, "") for k in fields})

    print("Exported {} messages to {}".format(len(records), output_path))


# --- CLI ---

def main():
    parser = argparse.ArgumentParser(
        description="Export Signal Desktop messages on macOS (supports Signal >= 7.x safeStorage)."
    )
    parser.add_argument("--export", metavar="FILE", help="Export messages to CSV or JSON file")
    parser.add_argument("--conversation", metavar="NAME", help="Filter by conversation name (partial match)")
    parser.add_argument("--after", metavar="YYYY-MM-DD", help="Only messages after this date")
    parser.add_argument("--list-conversations", action="store_true", help="List all conversations")
    parser.add_argument("--print-key", action="store_true", help="Print the derived SQLCipher key and PRAGMA statement")
    args = parser.parse_args()

    print("Deriving SQLCipher key (may prompt for Keychain access)...")
    key = derive_sqlcipher_key()

    if args.print_key:
        print("\nSQLCipher key: " + key)
        print("PRAGMA key = \"x'" + key + "'\";")
        return

    if args.list_conversations:
        convos = list_conversations(key)
        print("\n{} conversations:\n".format(len(convos)))
        for c in convos:
            print("  " + c["name"])
        return

    if args.export:
        conversation_id = None
        if args.conversation:
            conversation_id = find_conversation_id(key, args.conversation)
        export_messages(key, args.export, conversation_id=conversation_id, after=args.after)
        return

    # Default: just print the key
    print("\nSQLCipher key: " + key)
    print("\nPRAGMA statement:")
    print("PRAGMA key = \"x'" + key + "'\";")
    print("\nRun with --help to see export options.")


if __name__ == "__main__":
    main()
