
import argparse
import getpass
import sys

sys.path.insert(0, ".")

from decrypt.decrypt import encrypt_credential


def _read_secret(prompt: str) -> str:
    value = getpass.getpass(prompt).strip()
    if not value:
        raise SystemExit("Secret value is required.")
    return value


parser = argparse.ArgumentParser(description="Generate encrypted Hunter Storage tokens.")
parser.add_argument("--owner-id", default="7141623505")
parser.add_argument("--upstream-url")
parser.add_argument("--session-password")
args = parser.parse_args()

owner_id = str(args.owner_id)
upstream_url = args.upstream_url or _read_secret("Upstream URL: ")
session_password = args.session_password or _read_secret("Session password: ")

print("=== NEW ENCRYPTED TOKENS ===")
print(f'InvalToken = "{encrypt_credential(upstream_url, owner_id)}"')
print(f'SESS_183_SESS = "{encrypt_credential(session_password, owner_id)}"')
