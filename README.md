# Enpass-Escape

A lightweight Python CLI to migrate Enpass website passwords to Apple Passwords or Google Password Manager.

## 🚀 Features

- Converts Enpass CSV or JSON export to Apple Passwords import CSV
- Converts website passwords to Google Password Manager CSV
- Keeps the newest safely identifiable duplicate by default
- Preserves TOTP/2FA secrets with proper otpauth URI formatting
- Maintains titles, URLs, usernames, passwords, and notes
- Combines any additional fields into organized notes
- Excludes archived and trashed items unless requested
- Writes output atomically with owner-only permissions
- Zero external dependencies except Typer for the CLI interface

## 📋 Prerequisites

- Python 3.11 or higher

## 🛠️ Installation

Install from PyPI:

```bash
pip install enpass-escape
```

Or install development version:

```bash
git clone https://github.com/ake2l/enpass-apple-migrator.git
cd enpass-apple-migrator
pip install -e .
```

## 💻 Usage

> **Note:** The Enpass CSV export does not support all fields completely (e.g., TOTP, notes, extra fields). For best results, it is recommended to use the **JSON export** from Enpass!

Run the `enpass-escape` command with your Enpass export and desired output path:

```bash
# CSV-to-CSV
enpass-escape enpass-export.csv export-apple-passwords.csv

# JSON-to-CSV
enpass-escape export.json apple-output.csv

# Google Password Manager; website passwords only
enpass-escape export.json google-output.csv --target google

# Analyze without creating a plaintext export
enpass-escape export.json --target google --dry-run

# Keep all duplicates
enpass-escape export.json apple-output.csv --duplicates keep

# Include archived items
enpass-escape export.json apple-output.csv --include-archived

# Replace an existing output file
enpass-escape export.json apple-output.csv --force

# View help
enpass-escape --help
```

The output CSV will have the header:

```csv
Title,URL,Username,Password,Notes,OTPAuth
```

### Input Formats

- **JSON (recommended)**: Enpass JSON export (recommended for complete data export)
- **CSV**: Standard Enpass CSV export (limited field support)

### Output Formats

Apple Passwords import CSV with the following columns:

```csv
Title,URL,Username,Password,Notes,OTPAuth
```

Google Password Manager CSV:

```csv
url,username,password,note
```

Google exports contain only entries with an HTTP(S) URL and a password. Files are split automatically at Google's 3,000-entry import limit. TOTP secrets and passkeys are not exported to Google.

### Duplicates

- `newest` (default): keep the entry with the highest Enpass `updated_at` for the same normalized URL and username
- `exact`: remove only entries with identical migrated content
- `keep`: do not remove duplicates

Entries with missing or tied timestamps are kept when their content differs. CSV exports usually have no timestamps, so JSON is recommended for `newest`.

## 🔒 Security Considerations

- All processing is local; no network calls
- No data is stored or cached
- Output files are unencrypted and readable only by their owner
- No external dependencies other than Typer
- Delete the output after importing it successfully

## 🤝 Contributing

Contributions welcome! Open an issue or submit a pull request.

## 📝 License

MIT License. See [LICENSE](LICENSE) for details.
