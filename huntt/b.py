import os
from decrypt import decrypt

# Try to import encrypted URLs from cryptograph, fallback to hardcoded if not available
try:
    from cryptograph.fernet import ENCRYPTED_DATABASE_URL, DATABASE_URL_VERIFY
except ImportError:
    # Fallback to hardcoded encrypted strings if module import fails
    ENCRYPTED_DATABASE_URL = ""
    DATABASE_URL_VERIFY = ""

# Encrypted credentials
ENCRYPTED_BOT_TOKEN = ""
owner = 0
api = 0                    
hash = ""
# Decrypt credentials - use owner_id as password for verify/payment URLs
_decrypt_password = os.getenv("DECRYPT_PASSWORD", str(owner))
_decrypted_bot_token = decrypt(ENCRYPTED_BOT_TOKEN, _decrypt_password)
_decrypted_database_url = decrypt(ENCRYPTED_DATABASE_URL, _decrypt_password)

bot_data = bots = {
    "godx": {
        "BOT_TOKEN": _decrypted_bot_token,
        "OWNER_ID": 0,
        "DATABASE_URL": _decrypted_database_url,
        "TELEGRAM_API": 0,                       
        "TELEGRAM_HASH": ""                         
    },
}

# Decrypt verify and payment database URLs
try:
    decrypted_payment_db = decrypt(ENCRYPTED_DATABASE_URL, _decrypt_password)
    decrypted_verify_db = decrypt(DATABASE_URL_VERIFY, _decrypt_password)

    # Inject Verify and Payment DB URLs into all bots
    for bot_conf in bots.values():
        if "DATABASE_URL_PAYMENT" not in bot_conf:
            bot_conf["DATABASE_URL_PAYMENT"] = decrypted_payment_db
        if "DATABASE_URL_VERIFY" not in bot_conf:
            bot_conf["DATABASE_URL_VERIFY"] = decrypted_verify_db
except Exception:
    pass
