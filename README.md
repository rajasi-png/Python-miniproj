# SecureQR — password-gated prototype

SecureQR is a Django prototype that encrypts sensitive records and generates a QR code
containing only an opaque URL for the encrypted record. The record page asks for a
password, then decrypts the record only after the password authenticates the wrapped key.

> **Security model:** encryption and password-authenticated decryption happen on the server
> with AES-256-GCM. This is **not end-to-end encryption**: the server sees the password and
> plaintext during unlock. Device authorization, rate limiting, and client-side decryption
> are future work.

---

## What the application does

A single page at `/` lets the user:

1. Enter a record title, secret content, and an unlock password.
2. Optionally enter a reference URL or photo.
3. Encrypt the record and generate a QR code.
4. Copy the record URL or download the QR PNG.
5. Open the QR URL, enter the password, and view the decrypted record.

The QR destination is `/r/<random-token>/`. It shows ciphertext and encryption metadata.
It does **not** decrypt anything, and it exposes no plaintext.

There is no dashboard, admin route, verification route, or decryption route.

---

## Encryption design

### Per record

- A random **256-bit data-encryption key (DEK)** is generated with `secrets.token_bytes(32)`.
- A fresh **96-bit nonce** is generated for AES-GCM.
- The title, content, and optional URL are serialized as JSON and encrypted with
  **AES-256-GCM**.
- The associated data binds the ciphertext to the record token and envelope version.
- The DEK is wrapped with the **master key** using AES-256-GCM and a separate fresh nonce.
- The same DEK is also wrapped with a **password-derived key** using AES-256-GCM.
- The password key comes from PBKDF2-HMAC-SHA256 with a random salt and a stored iteration
  count. The password itself is never stored.
- The wrapped DEK is bound to the record token and key version with associated data.
- The database stores the ciphertext, nonces, both wrapped DEKs, the salt, iteration count,
  key version, random token, and creation time. It stores no plaintext password, title,
  content, URL, raw DEK, or master key.

### Password unlock

Opening the QR URL shows a password form. The submitted password is used only on the
server to re-derive the password key and unwrap the DEK. If AES-GCM authentication fails,
the response is a generic unlock error with no plaintext. The master-wrapped DEK remains
for internal/test decryption; the web route never uses the master key to decrypt.

### Record URL and QR

- The public record identifier is a 256-bit URL-safe random token, not a sequential ID.
- The QR code contains only the absolute URL such as
  `http://127.0.0.1:8000/r/<token>/`.
- It never contains plaintext, a data key, the master key, or a private key.
- Knowing the URL allows someone to reach the password screen, but not to decrypt the
  record without the password.

### Web and internal decryption

The password-gated route calls `unlock_record()` in `website/services.py`. It derives the
password key, unwraps the DEK, and decrypts the payload only after AES-GCM authentication
succeeds. `website/crypto.py` also contains an internal `decrypt_payload()` function used
by tests and future server-side tooling; no unrestricted decryption endpoint exists.

### Metadata authentication

AES-GCM authenticates ciphertext. The additional associated data (AAD) also binds:

- the record token to the payload ciphertext, and
- the record token and key version to the wrapped data key.

If ciphertext, nonces, wrapped key material, the record token, or the key version is
changed, authentication fails.

---

## Master-key management

All master-key access is isolated in `website/key_management.py` so Phase 2 can replace it
with per-device key wrapping and authorization.

The default local development path is:

```text
D:\QR Code Generetor\QR\secureqr_keys\master.key
```

The file contains a Base64-encoded 32-byte key. It is:

- outside `static/` and media folders,
- ignored by Git through `.gitignore`,
- never stored in SQLite,
- never sent to the browser or placed in a QR code,
- never generated automatically when Django starts.

If the master key is missing or malformed, encryption fails safely. The page shows setup
instructions and the submit button is disabled. Existing records are not silently
re-encrypted with a replacement key.

### Create the key once

Use the explicit setup command:

```powershell
python manage.py init_master_key
```

The command refuses to overwrite an existing key. Do not delete or replace the key after
creating records, because their wrapped data keys depend on it. Back up the key securely.

### Environment-variable option

The loader checks `SECUREQR_MASTER_KEY` first. Its value must be a Base64-encoded 32-byte
key. If it is set, it takes precedence over the file and `init_master_key` will not create a
file. Use one method consistently.

PowerShell example for the current session:

```powershell
$env:SECUREQR_MASTER_KEY = & "..\venv\Scripts\python.exe" -c "import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

Never commit this value or paste it into the application UI.

**Windows note:** Python's `chmod` is best-effort on Windows. Restrict the project folder
with Windows account permissions, and do not place it in a shared or public directory.

---

## Project structure

```text
QR Code Generetor/
├── venv/
└── QR/
    ├── manage.py
    ├── db.sqlite3
    ├── requirements.txt
    ├── README.md
    ├── .gitignore
    ├── QR/
    │   ├── settings.py
    │   └── urls.py
    └── website/
        ├── crypto.py                    # AES-256-GCM and DEK wrapping
        ├── key_management.py            # master-key loading/creation
        ├── services.py                  # payload, token, QR helpers
        ├── models.py                    # encrypted-record envelope
        ├── forms.py                     # input validation
         ├── views.py                     # generator and password-gated retrieval

        ├── urls.py
        ├── migrations/0001_initial.py
        ├── migrations/0002_encryptedrecord_image_ciphertext_and_more.py
        ├── migrations/0003_add_password_unlock_fields.py
        ├── management/commands/
        │   └── init_master_key.py
        ├── templates/
        │   ├── base.html
        │   └── website/
         │       ├── generator.html
         │       ├── record_detail.html
         │       └── record_unlocked.html

        ├── static/website/
        │   ├── css/style.css
        │   └── js/app.js
        └── tests.py
```

---

## Windows setup and run commands

The folder on disk is spelled `QR Code Generetor` (with “Generetor”), so these commands use
that actual path.

```powershell
cd "D:\QR Code Generetor\QR"
..\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python manage.py migrate
python manage.py init_master_key
python manage.py runserver
```

Open <http://127.0.0.1:8000/> in a standalone browser tab.

> **Do not use an IDE embedded preview, sandboxed iframe, or a `file://` URL for the
> form.** Those contexts send `Origin: null`, which Django correctly rejects as an
> untrusted CSRF origin. SecureQR also sends `Content-Security-Policy: frame-ancestors
> 'none'` and shows an "Open SecureQR directly" notice if it detects an embedded frame.
> CSRF protection is never disabled to accommodate a preview pane.

### If CSRF still fails

Use the project virtual environment and run exactly one development server. Duplicate
`runserver` processes can both listen on port 8000 and serve stale settings or code.

```powershell
# List Python runserver processes
Get-CimInstance Win32_Process |
    Where-Object { $_.Name -eq "python.exe" -and $_.CommandLine -like "*manage.py runserver*" } |
    Select-Object ProcessId, CreationDate, CommandLine

# Stop any duplicate/stale servers
Get-CimInstance Win32_Process |
    Where-Object { $_.Name -eq "python.exe" -and $_.CommandLine -like "*manage.py runserver*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }

# Start exactly one server from this project's venv
cd "D:\QR Code Generetor\QR"
..\venv\Scripts\python.exe manage.py runserver 127.0.0.1:8000
```

In `DEBUG=True`, the server prints one `CSRF diagnostics:` line before CSRF validation
for each unsafe request. It includes method, path, Origin, Referer, content type, whether
the CSRF cookie exists, host, and `Sec-Fetch-*` hints. It never prints form values, cookie
values, or CSRF tokens.

A native same-origin form POST reports `sec_fetch_site=same-origin`,
`sec_fetch_dest=document`, and `sec_fetch_mode=navigate`. Under
`Referrer-Policy: no-referrer`, Chromium-based browsers including Brave send
`Origin: null` for those form POSTs even though the page origin is normal. SecureQR now
uses `Referrer-Policy: strict-origin`, which sends only scheme/host/port as the Referer,
does not expose record paths or tokens, and preserves the real Origin for CSRF checks.
If `origin=null` still appears, confirm the response header is `Referrer-Policy:
strict-origin` and retry with browser extensions/Shields temporarily disabled.

If PowerShell blocks activation:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Only run `init_master_key` once. If it reports that the key already exists, keep the
existing key.

### Optional: scan the QR from a phone on the same network

Start Django on all interfaces:

```powershell
$env:DJANGO_ALLOWED_HOSTS = "localhost,127.0.0.1,192.168.1.50"
$env:DJANGO_CSRF_TRUSTED_ORIGINS = "http://127.0.0.1:8000,http://192.168.1.50:8000"
python manage.py runserver 0.0.0.0:8000
```

Replace `192.168.1.50` with the computer's LAN IP, and open the app using that same IP
(`http://192.168.1.50:8000/`) so the QR encodes a phone-reachable URL. The CSRF trusted
origin must exactly match that same scheme, host, and port. Use only a trusted local
network.

---

## Tests

```powershell
cd "D:\QR Code Generetor\QR"
..\venv\Scripts\Activate.ps1
python manage.py check
python manage.py test
```

The test suite uses temporary master keys, so it does not read or change the real
`secureqr_keys/master.key`.

Coverage includes:

- master-key loading, missing/malformed key handling, environment-variable precedence,
  and refusal to overwrite an existing key,
- AES-256-GCM round trip,
- different keys and nonces for separate encryption operations,
- tampered ciphertext, nonce, wrapped key, AAD token, and wrong master key rejection,
- malformed envelope handling,
- password-derived key wrapping, wrong-password rejection, and AAD binding,
- input validation, including short/blank passwords and unsafe URL schemes,
- CSRF rejection without a token on creation and unlock,
- QR content containing only the record URL,
- full create → password screen → wrong password → correct password → decrypted text/URL/image
  workflow,
- plaintext and key material absent from the database, HTML responses, QR content, and logs,
- missing and malformed records returning 404,
- no unrestricted decryption or admin routes.

Latest local run: **61 tests passed** and `manage.py check` reported no issues.

---

## Security limitations (important for the viva)

- **Server-side encryption only.** The server receives the plaintext while encrypting and
  holds the master key, so this is not end-to-end encryption.
- **Password, not device authorization.** Opening the QR URL is not proof that a device is
  trusted. The password authenticates the wrapped key; there is no device registration,
  pairing, approval, or revocation.
- **Server-side decryption.** The server sees the submitted password and plaintext during
  unlock, but never sends key material to the browser.
- **URL holders reach the password screen.** The token is unguessable, but anyone who obtains
  the URL can try passwords. Add rate limiting before production deployment.
- **No key rotation.** `key_version` is stored so a future version can support rotation, but
   This prototype has one master key.

- **Local prototype settings.** `DEBUG=True` and HTTP are used for development. Production
  needs HTTPS, `DEBUG=False`, secure hosting, restricted file permissions, and backups.
- **Python memory.** Keys and plaintext exist in process memory during encryption and
  internal decryption. Python does not provide guaranteed secure memory wiping.
- **SQLite** is suitable for this prototype, not a high-security multi-user deployment.

---

## Simple viva explanation

1. The user enters a title, secret content, an optional URL/photo, and an unlock password.
2. Django validates the form. On a validation error, the form is cleared instead of echoing
   the secret back into the HTML.
3. The server creates a random record token and a random 256-bit data key.
4. The record data becomes JSON and is encrypted with AES-256-GCM using a fresh nonce.
5. The data key is wrapped twice: once with the server master key and once with a key derived
   from the password using PBKDF2 and a random salt. The plaintext password is never stored.
6. The ciphertext, nonces, wrapped keys, salt, and metadata are saved in SQLite.
7. The QR code is generated from the record URL only. The URL contains the random token.
8. Opening the URL shows a password form. Only a password that unwraps the AES-GCM protected
   data key causes the record, URL, and photo to be decrypted and displayed.
9. Future work can add device authorization, rate limiting, and browser-side decryption.

---

## Dependencies

- Django (installed in the existing virtual environment)
- `cryptography` for AES-256-GCM
- `qrcode[pil]` for QR PNG generation
- Bootstrap 5 from CDN and a small amount of vanilla JavaScript
