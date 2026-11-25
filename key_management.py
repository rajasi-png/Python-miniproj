import base64
import binascii
import os
import secrets
from pathlib import Path

from django.conf import settings

MASTER_KEY_BYTES = 32


class MasterKeyConfigurationError(RuntimeError):
    """Raised when the development master key is missing or malformed."""


def _decode_key(encoded_key, source):
    try:
        key = base64.b64decode(encoded_key.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MasterKeyConfigurationError(
            f"{source} is not valid Base64. The master key must be Base64 encoded."
        ) from exc

    if len(key) != MASTER_KEY_BYTES:
        raise MasterKeyConfigurationError(
            f"{source} contains {len(key)} bytes. The master key must be exactly 32 bytes."
        )
    return key


def load_master_key():
    """Load the 32-byte master key from the environment or the local key file.

    The key is never generated here. Missing configuration must fail instead of
    silently replacing the key, because that would make existing records
    impossible to decrypt.
    """
    env_name = settings.SECUREQR_MASTER_KEY_ENV
    env_value = os.environ.get(env_name, "").strip()
    if env_value:
        return _decode_key(env_value, f"Environment variable {env_name}")

    key_path = Path(settings.SECUREQR_MASTER_KEY_FILE)
    if not key_path.is_file():
        raise MasterKeyConfigurationError(
            "SecureQR master key is not configured.\n"
            "Create it once with: python manage.py init_master_key\n"
            f"Or set {env_name} to a Base64-encoded 32-byte key."
        )

    try:
        encoded_key = key_path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise MasterKeyConfigurationError(
            f"The master key file could not be read as ASCII: {key_path}"
        ) from exc

    return _decode_key(encoded_key, f"Key file {key_path}")


def master_key_is_configured():
    """Return True only when a valid key can be loaded."""
    try:
        load_master_key()
    except (MasterKeyConfigurationError, OSError):
        return False
    return True


def create_master_key_file(path=None):
    """Create a new master-key file without ever overwriting an existing one."""
    env_name = settings.SECUREQR_MASTER_KEY_ENV
    if os.environ.get(env_name, "").strip():
        raise MasterKeyConfigurationError(
            f"{env_name} is already set. No key file was created."
        )

    key_path = Path(path or settings.SECUREQR_MASTER_KEY_FILE)
    if key_path.exists():
        raise MasterKeyConfigurationError(
            f"A master key already exists at {key_path}. It was not overwritten."
        )

    try:
        key_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise MasterKeyConfigurationError(
            f"The master key directory could not be created at {key_path.parent}."
        ) from exc

    try:
        os.chmod(key_path.parent, 0o700)
    except OSError:
        # Windows does not apply POSIX permission bits in the same way.
        pass

    key = secrets.token_bytes(MASTER_KEY_BYTES)
    encoded_key = base64.b64encode(key).decode("ascii") + "\n"

    try:
        # The "x" mode refuses to overwrite an existing file.
        with key_path.open("x", encoding="ascii", newline="\n") as key_file:
            key_file.write(encoded_key)
    except OSError as exc:
        if key_path.exists():
            try:
                key_path.unlink()
            except OSError:
                pass
        raise MasterKeyConfigurationError(
            f"The master key file could not be created at {key_path}."
        ) from exc

    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass

    return key_path
