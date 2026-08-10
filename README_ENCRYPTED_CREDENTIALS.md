# Hunter Storage - Encrypted Credentials

This repository now uses **encrypted credentials** for enhanced security. All sensitive data (bot tokens, database URLs, git tokens) are stored in encrypted form rather than plaintext.

## 🔐 Security Enhancements

- **Git tokens with credentials**: Now encrypted in `cryptograph/fernet.py`  
- **Database URLs**: Now encrypted across multiple modules
- **Bot tokens**: Now encrypted in `huntt/b.py`
- **Runtime decryption**: Automatic decryption when modules are imported
- **Environment-based password**: Uses `DECRYPT_PASSWORD` environment variable

## 📁 Updated Files

### `cryptograph/fernet.py`
- Contains encrypted `DATA` (MongoDB URL) and `GIT_TOKEN`
- Automatically decrypts at import time
- Uses existing `decrypt` module

### `huntt/b.py`  
- Contains encrypted bot configuration data
- `BOT_TOKEN` and `DATABASE_URL` are now encrypted
- Maintains the same interface for consuming code

### `update.py` (renamed from `update (4).py`)
- Enhanced with encrypted credential support
- Can handle both encrypted and plaintext upstream repositories
- Automatic detection and decryption of credentials
- Improved error handling and logging

### `token_db/token_db.py`
- Uses encrypted database URL from `cryptograph` module
- No changes needed - works automatically with encrypted credentials

## 🚀 Usage

### Environment Setup
```bash
export DECRYPT_PASSWORD="your_secure_password_here"
```
**Default password (for testing):** `hunter2024`

### Using the modules
```python
# Import modules - automatic decryption happens
from cryptograph import DATA, GIT_TOKEN, NAME
from huntt import bots

# Use normally
database_url = DATA  
bot_token = bots["godx"]["BOT_TOKEN"]
```

### Running the update script
```bash
python update.py
```
The script will automatically decrypt any encrypted credentials it encounters.

## 🔧 Technical Details

- **Encryption**: AES-256 with PBKDF2 key derivation (existing `decrypt` module)
- **Backward compatibility**: Falls back to original values if decryption fails
- **Error handling**: Graceful handling of missing passwords or invalid encrypted data
- **Security**: No plaintext credentials remain in source code

## 🛡️ Security Benefits

1. **Source code safety**: No sensitive credentials visible in code
2. **Version control safe**: Encrypted strings can be committed safely  
3. **Environment isolation**: Different passwords for different environments
4. **Access control**: Only those with decryption password can use credentials

## 📚 Files Added

- `.gitignore`: Prevents Python cache files from being committed
- `update.py`: Enhanced update script (renamed from `update (4).py`)

---

**Note**: Keep your `DECRYPT_PASSWORD` secure and never commit it to version control. Use different passwords for different environments (dev/staging/prod).