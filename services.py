import base64
import json
import re
import secrets
from io import BytesIO

import qrcode
from django.conf import settings
from django.urls import reverse

from .crypto import (
    DATA_KEY_BYTES,
    DecryptionError,
    UnlockNotConfiguredError,
    decrypt_payload_with_data_key,
    encrypt_payload,
    new_password_key,
    unwrap_data_key_with_password,
    wrap_data_key_with_password_key,
)
from .models import EncryptedRecord

RECORD_TOKEN_BYTES = 32
RECORD_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
PAYLOAD_VERSION = 1
ALLOWED_IMAGE_CONTENT_TYPES = {"image/jpeg", "image/png", "image/webp"}


def generate_record_token():
    """Return a cryptographically random, non-sequential public identifier."""
    return secrets.token_urlsafe(RECORD_TOKEN_BYTES)


def is_valid_record_token(token):
    return bool(RECORD_TOKEN_PATTERN.fullmatch(token or ""))


def build_secret_payload(title, content, source_url, image_metadata=None):
    """Create the JSON bytes that will be encrypted as one record."""
    payload = {
        "version": PAYLOAD_VERSION,
        "title": title,
        "content": content,
        "url": source_url or None,
        "image": image_metadata,
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def build_encrypted_record(
    *,
    title,
    content,
    source_url,
    master_key,
    password,
    image_bytes=None,
    image_metadata=None,
):
    """Encrypt a record and return an unsaved password-protected model instance."""
    if (image_bytes is None) != (image_metadata is None):
        raise ValueError("Image bytes and metadata must be provided together.")
    if not password:
        raise ValueError("A password is required.")

    token = generate_record_token()
    plaintext = build_secret_payload(
        title,
        content,
        source_url,
        image_metadata=image_metadata,
    )
    password_key = new_password_key(password)
    payload_data_key = secrets.token_bytes(DATA_KEY_BYTES)
    encrypted = encrypt_payload(
        plaintext,
        token,
        master_key,
        key_version=settings.SECUREQR_KEY_VERSION,
        data_key=payload_data_key,
    )
    wrapped_payload_key = wrap_data_key_with_password_key(
        password_key,
        payload_data_key,
        token,
        "payload",
    )

    password_fields = {
        "password_salt": password_key.salt,
        "password_wrapped_data_key": wrapped_payload_key.wrapped_data_key,
        "password_key_nonce": wrapped_payload_key.nonce,
        "password_iterations": password_key.iterations,
    }

    image_fields = {}
    if image_bytes is not None:
        image_data_key = secrets.token_bytes(DATA_KEY_BYTES)
        encrypted_image = encrypt_payload(
            image_bytes,
            token,
            master_key,
            key_version=settings.SECUREQR_KEY_VERSION,
            data_key=image_data_key,
        )
        wrapped_image_key = wrap_data_key_with_password_key(
            password_key,
            image_data_key,
            token,
            "image",
        )
        image_fields = {
            "image_ciphertext": encrypted_image.ciphertext,
            "image_nonce": encrypted_image.nonce,
            "image_wrapped_data_key": encrypted_image.wrapped_data_key,
            "image_key_nonce": encrypted_image.key_nonce,
            "image_key_version": encrypted_image.key_version,
            "image_password_wrapped_data_key": wrapped_image_key.wrapped_data_key,
            "image_password_key_nonce": wrapped_image_key.nonce,
        }

    return EncryptedRecord(
        token=token,
        ciphertext=encrypted.ciphertext,
        nonce=encrypted.nonce,
        wrapped_data_key=encrypted.wrapped_data_key,
        key_nonce=encrypted.key_nonce,
        key_version=encrypted.key_version,
        **password_fields,
        **image_fields,
    )


def build_image_data_uri(image_bytes, content_type):
    if content_type not in ALLOWED_IMAGE_CONTENT_TYPES:
        raise DecryptionError("The decrypted image has an unsupported type.")
    encoded = base64.b64encode(bytes(image_bytes)).decode("ascii")
    return f"data:{content_type};base64,{encoded}"


def unlock_record(record, password):
    """Authenticate a password, then decrypt a record for the current response."""
    if not (
        record.password_salt
        and record.password_wrapped_data_key
        and record.password_key_nonce
        and record.password_iterations
    ):
        raise UnlockNotConfiguredError(
            "This record was created without password unlock data."
        )

    payload_data_key = unwrap_data_key_with_password(
        record.token,
        "payload",
        password,
        bytes(record.password_salt),
        record.password_iterations,
        bytes(record.password_wrapped_data_key),
        bytes(record.password_key_nonce),
    )
    plaintext = decrypt_payload_with_data_key(
        record.ciphertext,
        record.nonce,
        record.token,
        payload_data_key,
    )

    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise DecryptionError("The decrypted record is malformed.") from None

    if not isinstance(payload, dict) or payload.get("version") != PAYLOAD_VERSION:
        raise DecryptionError("The decrypted record has an unsupported version.")

    title = payload.get("title")
    content = payload.get("content")
    source_url = payload.get("url")
    if not isinstance(title, str) or not isinstance(content, str):
        raise DecryptionError("The decrypted record is malformed.")
    if source_url is not None and not isinstance(source_url, str):
        raise DecryptionError("The decrypted record is malformed.")
    if source_url and not source_url.startswith(("http://", "https://")):
        source_url = None

    metadata = payload.get("image")
    image_data_uri = None
    if record.has_image:
        if not isinstance(metadata, dict):
            raise DecryptionError("The decrypted image metadata is malformed.")
        if not (
            record.image_password_wrapped_data_key
            and record.image_password_key_nonce
        ):
            raise UnlockNotConfiguredError(
                "This record's image has no password unlock data."
            )
        image_data_key = unwrap_data_key_with_password(
            record.token,
            "image",
            password,
            bytes(record.password_salt),
            record.password_iterations,
            bytes(record.image_password_wrapped_data_key),
            bytes(record.image_password_key_nonce),
        )
        image_bytes = decrypt_payload_with_data_key(
            record.image_ciphertext,
            record.image_nonce,
            record.token,
            image_data_key,
        )
        image_data_uri = build_image_data_uri(
            image_bytes,
            metadata.get("content_type"),
        )

    return {
        "title": title,
        "content": content,
        "url": source_url,
        "image_data_uri": image_data_uri,
        "image_metadata": metadata if isinstance(metadata, dict) else None,
        "has_image": record.has_image,
    }


def build_record_url(request, record):
    path = reverse("website:record_detail", kwargs={"token": record.token})
    return request.build_absolute_uri(path)


def generate_qr_png(record_url):
    """Encode only the record URL, never secrets or key material."""
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(record_url)
    qr.make(fit=True)

    image = qr.make_image(fill_color="#0b2240", back_color="white").convert("RGB")
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def png_data_uri(png_bytes):
    encoded_png = base64.b64encode(png_bytes).decode("ascii")
    return f"data:image/png;base64,{encoded_png}"


def bytes_to_base64(value):
    return base64.b64encode(bytes(value)).decode("ascii")
