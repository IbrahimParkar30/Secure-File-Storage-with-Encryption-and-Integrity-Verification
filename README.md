# Secure File Storage — AES-256 + Custom Blockchain

A college-level Python/Flask web application that demonstrates:

- **AES-256 CBC encryption** of uploaded files (PyCryptodome)
- **SHA-256 integrity fingerprinting** of every encrypted file
- A **custom in-process blockchain** (stored as `chain.json`) that permanently records each file's name and hash
- **Tamper detection** on download — any modification to the encrypted file is detected instantly

---

## Project Structure

```
secure_file_storage/
├── app.py              # Flask application & routes
├── blockchain.py       # Block, Blockchain classes
├── encryption.py       # AES-256 encrypt / decrypt helpers
├── requirements.txt    # Python dependencies
├── chain.json          # Blockchain persistence (auto-managed)
├── aes.key             # AES-256 key file (auto-generated on first run)
├── README.md
│
├── uploads/            # Temporary plaintext store (cleared after encryption)
├── encrypted/          # Permanent encrypted file store (.enc files)
├── decrypted/          # Temporary decryption output for download streaming
│
└── templates/
    ├── index.html          # Home / upload page
    ├── upload_result.html  # Upload confirmation + block details
    ├── download.html       # File listing / download selection
    ├── download_result.html# Integrity result + decrypted download
    ├── verify.html         # Standalone integrity check form
    └── chain.html          # Full blockchain explorer
```

---

## Requirements

- Python 3.10 or higher (uses `list[Block]` and `Block | None` type hints)
- pip

---

## Installation

```bash
# 1. Clone or unzip the project
cd secure_file_storage

# 2. (Recommended) Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate      # Linux / macOS
# or
venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Running the Application

```bash
python app.py
```

Then open your browser at: **http://127.0.0.1:5000**

On first run the app will:
1. Create the `uploads/`, `encrypted/`, and `decrypted/` folders automatically.
2. Generate a fresh 256-bit AES key saved to `aes.key`.
3. Load (or initialise) the blockchain from `chain.json`.

---

## Usage

| Page | URL | Description |
|------|-----|-------------|
| Home / Upload | `/` | Upload a file to encrypt and record |
| Download | `/download` | List stored files; verify + download |
| Verify | `/verify` | Check integrity without downloading |
| Blockchain | `/chain` | Browse all blockchain blocks |

### Upload a file
1. Go to `http://127.0.0.1:5000`
2. Drag-and-drop or select a file.
3. Click **Encrypt & Upload**.
4. The result page shows the SHA-256 hash and the new blockchain block.

### Download / Verify a file
1. Go to `/download`.
2. Click **Verify & Download** next to the file.
3. The app re-hashes the encrypted file and compares it with the blockchain record.
   - ✅ Match → decrypts and streams the file to your browser.
   - ⚠️ Mismatch → displays **"FILE TAMPERED!"** and blocks the download.

---

## How to Test Tamper Detection

1. Upload any file (e.g. `test.txt`).
2. Locate `encrypted/test.txt.enc`.
3. Open it in a hex editor (or run `echo "tampered" >> encrypted/test.txt.enc` in the terminal).
4. Go to `/download` and click **Verify & Download** for `test.txt`.
5. You should see the red **"FILE TAMPERED!"** banner with both hashes displayed.

---

## Security Notes

| Feature | Implementation |
|---------|---------------|
| Encryption | AES-256 in CBC mode, random IV per file, PKCS7 padding |
| Key storage | `aes.key` — keep this file secret and never commit it |
| Integrity | SHA-256 hash of the full encrypted file |
| Blockchain | SHA-256 of `index + timestamp + filename + file_hash + prev_hash` |
| Tamper detection | Hash recomputed on every download request |

> **Production note:** `aes.key` should be stored outside the web root or loaded from an environment variable. The `FLASK_SECRET` environment variable controls the Flask session secret key.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| Flask | Web framework |
| pycryptodome | AES-256 encryption (`Crypto.Cipher.AES`) |
| Werkzeug | Secure filename sanitisation (bundled with Flask) |

---

## License

MIT — for educational / academic use.
