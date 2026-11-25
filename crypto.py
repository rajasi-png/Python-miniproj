import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.conf import settings

ALGORITHM = "AES-256-GCM"
DATA_KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
ENVELOPE_VERSION = 1
PASSWORD_SALT_BYTES = 16
PASSWORD_ENVELOPE_VERSION = 1


class EncryptionError(RuntimeError):
    """Raised when a record cannot be encrypted."""


class DecryptionError(RuntimeError):
    """Raised when ciphertext cannot be authenticated or decrypted."""


class PasswordUnlockError(DecryptionError):
    """Raised when a password-protected envelope cannot be unlocked."""


class InvalidPasswordError(PasswordUnlockError):
    """Raised when password-derived key authentication fails."""


class UnlockNotConfiguredError(PasswordUnlockError):
    """Raised when a record has no password unlock data."""


@dataclass(frozen=True)
class EncryptedPayload:
    ciphertext: bytes
    nonce: bytes
    wrapped_data_key: bytes
    key_nonce: bytes
    key_version: int = 1


@dataclass(frozen=True)
class PasswordKeyMaterial:
    key: bytes
    salt: bytes
    iterations: int


@dataclass(frozen=True)
class PasswordWrappedKey:
    wrapped_data_key: bytes
    nonce: bytes


def payload_aad(record_token, envelope_version=ENVELOPE_VERSION):
    """Bind ciphertext to the record token and the envelope format."""
    return f"secureqr|payload|v{envelope_version}|{record_token}".encode("utf-8")


def wrapping_aad(record_token, key_version):
    """Bind the wrapped data key to the record and master-key version."""
    return f"secureqr|data-key|v{key_version}|{record_token}".encode("utf-8")


def password_wrapping_aad(record_token, label):
    """Bind a password-wrapped key to the record and its envelope role."""
    value = (
        f"secureqr|password-key|v{PASSWORD_ENVELOPE_VERSION}|{record_token}|{label}"
    )
    return value.encode("utf-8")


def _validated_master_key(master_key, error_class):
    if not isinstance(master_key, (bytes, bytearray)) or len(master_key) != DATA_KEY_BYTES:
        raise error_class("The master key must be exactly 32 bytes.")
    return bytes(master_key)


def _validated_data_key(data_key, error_class):
    if not isinstance(data_key, (bytes, bytearray)) or len(data_key) != DATA_KEY_BYTES:
        raise error_class("The data key must be exactly 32 bytes.")
    return bytes(data_key)


def _validated_password(password, error_class):
    if not isinstance(password, str) or not password:
        raise error_class("A password is required.")
    return password


def _validated_iterations(iterations, error_class):
    try:
        value = int(iterations)
    except (TypeError, ValueError):
        raise error_class("The password KDF iteration count is invalid.") from None
    if value < 1:
        raise error_class("The password KDF iteration count is invalid.")
    return value


def new_password_key(password):
    """Derive a fresh password KEK and its salt for one record."""
    password = _validated_password(password, EncryptionError)
    salt = secrets.token_bytes(PASSWORD_SALT_BYTES)
    iterations = _validated_iterations(
        settings.SECUREQR_PASSWORD_ITERATIONS, EncryptionError
    )
    derived = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=DATA_KEY_BYTES,
        salt=salt,
        iterations=iterations,
    ).derive(password.encode("utf-8"))
    return PasswordKeyMaterial(key=derived, salt=salt, iterations=iterations)


def derive_password_key(password, salt, iterations):
    """Re-derive a record's password KEK from a submitted password."""
    password = _validated_password(password, DecryptionError)
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != PASSWORD_SALT_BYTES:
        raise PasswordUnlockError("The password salt is malformed.")
    value = _validated_iterations(iterations, DecryptionError)
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=DATA_KEY_BYTES,
        salt=bytes(salt),
        iterations=value,
    ).derive(password.encode("utf-8"))


def wrap_data_key_with_password_key(password_key, data_key, record_token, label):
    """Wrap a data key with a record's password-derived KEK using AES-GCM."""
    data_key = _validated_data_key(data_key, EncryptionError)
    nonce = secrets.token_bytes(NONCE_BYTES)
    try:
        wrapped = AESGCM(password_key.key).encrypt(
            nonce,
            data_key,
            password_wrapping_aad(record_token, label),
        )
    except Exception as exc:
        raise EncryptionError("The password-wrapped key could not be created.") from exc
    return PasswordWrappedKey(wrapped_data_key=wrapped, nonce=nonce)


def unwrap_data_key_with_password(
    record_token,
    label,
    password,
    salt,
    iterations,
    wrapped_data_key,
    nonce,
):
    """Unwrap a data key only when the submitted password authenticates."""
    if not salt or not wrapped_data_key or not nonce:
        raise UnlockNotConfiguredError("This record has no password unlock data.")
    if len(nonce) != NONCE_BYTES or len(wrapped_data_key) < DATA_KEY_BYTES + TAG_BYTES:
        raise PasswordUnlockError("The password-wrapped key is malformed.")

    derived = derive_password_key(password, salt, iterations)
    try:
        data_key = AESGCM(derived).decrypt(
            bytes(nonce),
            bytes(wrapped_data_key),
            password_wrapping_aad(record_token, label),
        )
    except InvalidTag:
        raise InvalidPasswordError("The password is incorrect.") from None
    return _validated_data_key(data_key, PasswordUnlockError)


def encrypt_payload(
    plaintext,
    record_token,
    master_key,
    key_version=1,
    data_key=None,
):
    """Encrypt bytes with a 256-bit data key and a fresh nonce."""
    if not isinstance(plaintext, (bytes, bytearray)):
        raise EncryptionError("The plaintext must be bytes.")
    if not record_token:
        raise EncryptionError("A record token is required.")

    master_key = _validated_master_key(master_key, EncryptionError)
    if data_key is None:
        data_key = secrets.token_bytes(DATA_KEY_BYTES)
    else:
        data_key = _validated_data_key(data_key, EncryptionError)

    nonce = secrets.token_bytes(NONCE_BYTES)
    key_nonce = secrets.token_bytes(NONCE_BYTES)

    try:
        ciphertext = AESGCM(data_key).encrypt(
            nonce,
            bytes(plaintext),
            payload_aad(record_token),
        )
        wrapped_data_key = AESGCM(master_key).encrypt(
            key_nonce,
            data_key,
            wrapping_aad(record_token, key_version),
        )
    except Exception as exc:
        raise EncryptionError("The record could not be encrypted.") from exc

    return EncryptedPayload(
        ciphertext=ciphertext,
        nonce=nonce,
        wrapped_data_key=wrapped_data_key,
        key_nonce=key_nonce,
        key_version=key_version,
    )


def unwrap_data_key(wrapped_data_key, key_nonce, record_token, master_key, key_version):
    """Unwrap a record's data key using the server-side master key."""
    master_key = _validated_master_key(master_key, DecryptionError)

    if len(key_nonce) != NONCE_BYTES or len(wrapped_data_key) < DATA_KEY_BYTES + TAG_BYTES:
        raise DecryptionError("The encrypted key metadata is malformed.")

    try:
        data_key = AESGCM(master_key).decrypt(
            key_nonce,
            wrapped_data_key,
            wrapping_aad(record_token, key_version),
        )
    except InvalidTag:
        raise DecryptionError(
            "The encrypted record could not be authenticated."
        ) from None

    return _validated_data_key(data_key, DecryptionError)


def decrypt_payload_with_data_key(ciphertext, nonce, record_token, data_key):
    """Decrypt an envelope with an already authenticated data key."""
    data_key = _validated_data_key(data_key, DecryptionError)
    if len(nonce) != NONCE_BYTES or len(ciphertext) < TAG_BYTES:
        raise DecryptionError("The encrypted record is malformed.")

    try:
        return AESGCM(data_key).decrypt(
            bytes(nonce),
            bytes(ciphertext),
            payload_aad(record_token),
        )
    except InvalidTag:
        raise DecryptionError(
            "The encrypted record could not be authenticated."
        ) from None


def decrypt_payload(encrypted, record_token, master_key):
    """Decrypt a record internally using the server-side master key."""
    data_key = unwrap_data_key(
        encrypted.wrapped_data_key,
        encrypted.key_nonce,
        record_token,
        master_key,
        encrypted.key_version,
    )
    return decrypt_payload_with_data_key(
        encrypted.ciphertext,
        encrypted.nonce,
        record_token,
        data_key,
    )
