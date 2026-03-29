# signal-export-mac

Export your Signal Desktop messages on macOS.

Most existing guides broke in mid-2024 when Signal migrated to storing the database encryption key via Electron's `safeStorage` API (backed by macOS Keychain + PBKDF2 derivation), replacing the previous plaintext key in `config.json`. This script handles both the old and new formats.

## Requirements

- macOS
- Signal Desktop (tested on 7.x+)
- Python 3.8+
- `sqlcipher` (`brew install sqlcipher`)
- `cryptography` (`pip install cryptography`)

## Usage

**Signal must be closed before running.**

```bash
# List all conversations
python3 signal_export.py --list-conversations

# Export all messages to CSV
python3 signal_export.py --export messages.csv

# Export all messages to JSON
python3 signal_export.py --export messages.json

# Export a single conversation
python3 signal_export.py --conversation "Beans" --export beans.csv

# Export messages after a date
python3 signal_export.py --after 2024-01-01 --export recent.csv

# Combine filters
python3 signal_export.py --conversation "Beans" --after 2024-01-01 --export beans_recent.csv

# Print the raw SQLCipher key (e.g. to use with DB Browser for SQLite)
python3 signal_export.py --print-key
```

macOS will prompt for your login password or Touch ID when the script accesses the Keychain. This is expected.

## How it works

Signal Desktop stores messages in an SQLCipher-encrypted SQLite database at:

```
~/Library/Application Support/Signal/sql/db.sqlite
```

Since Signal 7.x, the SQLCipher key is no longer stored in plaintext in `config.json`. Instead:

1. Signal generates a random key and stores it in `config.json` encrypted via Electron's `safeStorage` API
2. The safeStorage API on macOS uses Chromium's OSCrypt: the actual encryption password is stored in macOS Keychain under "Signal Safe Storage"
3. OSCrypt derives the AES-128-CBC key via PBKDF2-SHA1 (password = raw Keychain value, salt = `saltysalt`, iterations = 1003)
4. The IV is hardcoded to 16 space characters (0x20)
5. The encrypted key in `config.json` has a `v10` prefix followed by the ciphertext

This script replicates that derivation to recover the SQLCipher key, then uses the `sqlcipher` CLI to query and export your messages.

## CSV columns

| Column | Description |
|--------|-------------|
| `sent_at` | ISO 8601 timestamp |
| `type` | `incoming` / `outgoing` / `call-history` etc. |
| `body` | Message text |
| `conversationId` | Internal conversation ID |
| `source` | Sender phone number or UUID |
| `hasAttachments` | 1 if message has attachments |
| `id` | Internal message ID |

For richer data use `--export messages.json`, which includes the full message payload.

## Notes

- Attachments are stored separately under `~/Library/Application Support/Signal/attachments.noindex/` and are not exported by this script
- This script is for personal data export. It only works on your own machine with your own Signal data
- Tested on macOS Sequoia with Signal 8.4.1

## Credits

Chromium OSCrypt key derivation documented by [ControlPlane](https://control-plane.io/posts/abusing-vscode-from-malicious-extensions-to-stolen-credentials-part-2/).
