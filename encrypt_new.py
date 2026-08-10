import argparse
import getpass
import sys

from decrypt.decrypt import encrypt_credential, validate_stream


def _read_secret(prompt: str) -> str:
    value = getpass.getpass(prompt).strip()
    if not value:
        raise SystemExit("Secret value is required.")
    return value


def _emit(name: str, plaintext: str, password: str) -> str:
    encrypted = encrypt_credential(plaintext, password)
    if validate_stream(encrypted, password) != plaintext:
        raise SystemExit(f"{name} did not verify after encryption.")
    print(f'{name} = "{encrypted}"')
    return encrypted


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Encrypt Hunter Storage credentials without storing plaintext."
    )
    parser.add_argument("--owner-id", default="7141623505", help="Password/owner id used by runtime decryption.")
    parser.add_argument("--github-token", help="GitHub token to encrypt. If omitted, prompted securely.")
    parser.add_argument("--repo-url", help="Full upstream repository URL to encrypt.")
    parser.add_argument("--db-url", help="Database URL to encrypt.")
    args = parser.parse_args()

    password = str(args.owner_id)
    github_token = args.github_token or _read_secret("GitHub token: ")
    _emit("_API_ACCESS_TOKEN", github_token, password)

    if args.repo_url:
        _emit("InvalToken", args.repo_url, password)

    if args.db_url:
        encrypted_db = _emit("DATABASE_URL_VERIFY", args.db_url, password)
        print(f'ENCRYPTED_DATABASE_URL = "{encrypted_db}"')

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
