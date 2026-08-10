
import sys
sys.path.insert(0, '.')
from decrypt import decrypt
from cryptograph.fernet import InvalToken, SESS_183_SESS

OWNER_ID = '7141623505'

print('=== DECRYPTION CHECK ===')
upstream = decrypt(InvalToken, OWNER_ID)
sess_pass = decrypt(SESS_183_SESS, OWNER_ID)

if upstream.startswith("https://") and sess_pass:
    print("\nSUCCESS: Both tokens decrypt correctly!")
else:
    print("\nERROR: Decryption mismatch!")
