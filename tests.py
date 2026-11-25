import base64
import json
import logging
import os
import tempfile
from dataclasses import replace
from io import BytesIO, StringIO
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

import qrcode
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import OperationalError
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from PIL import Image

from .crypto import (
    DATA_KEY_BYTES,
    DecryptionError,
    EncryptedPayload,
    EncryptionError,
    InvalidPasswordError,
    PasswordUnlockError,
    decrypt_payload,
    derive_password_key,
    encrypt_payload,
    new_password_key,
    unwrap_data_key,
    unwrap_data_key_with_password,
    wrap_data_key_with_password_key,
)
from .forms import SecureRecordForm, UnlockForm
from .key_management import (
    MasterKeyConfigurationError,
    create_master_key_file,
    load_master_key,
    master_key_is_configured,
)
from .models import EncryptedRecord
from .services import is_valid_record_token

TEST_TOKEN = "A" * 43
TEST_MASTER_KEY = bytes(range(32))
TEST_PASSWORD = "correct horse battery staple 42"


def make_image_bytes(image_format="JPEG", size=(48, 32)):
    output = BytesIO()
    image = Image.new("RGB", size, (42, 120, 210))
    image.save(output, format=image_format)
    return output.getvalue()


def make_image_upload(filename="photo.jpg", image_format="JPEG"):
    content_type = {
        "JPEG": "image/jpeg",
        "PNG": "image/png",
        "WEBP": "image/webp",
    }[image_format]
    return SimpleUploadedFile(
        filename,
        make_image_bytes(image_format),
        content_type=content_type,
    )


class MasterKeyTestMixin:
    def setUp(self):
        super().setUp()
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)

        self.master_key = TEST_MASTER_KEY
        self.master_key_path = Path(self.temp_directory.name) / "master.key"
        self.master_key_path.write_text(
            base64.b64encode(self.master_key).decode("ascii") + "\n",
            encoding="ascii",
        )

        self.settings_override = override_settings(
            SECUREQR_MASTER_KEY_FILE=self.master_key_path,
            SECUREQR_PASSWORD_ITERATIONS=10_000,
        )
        self.settings_override.enable()
        self.addCleanup(self.settings_override.disable)

        self.env_patch = mock.patch.dict(os.environ, {"SECUREQR_MASTER_KEY": ""})
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)


class MasterKeyManagementTests(MasterKeyTestMixin, SimpleTestCase):
    def test_loads_valid_key_file(self):
        self.assertEqual(load_master_key(), self.master_key)
        self.assertTrue(master_key_is_configured())

    def test_missing_key_fails_with_setup_instructions(self):
        missing_path = Path(self.temp_directory.name) / "missing" / "master.key"
        with override_settings(SECUREQR_MASTER_KEY_FILE=missing_path):
            with self.assertRaisesRegex(MasterKeyConfigurationError, "init_master_key"):
                load_master_key()
            self.assertFalse(master_key_is_configured())

    def test_invalid_base64_fails_safely(self):
        self.master_key_path.write_text("not-valid-base64!!!", encoding="ascii")

        with self.assertRaisesRegex(MasterKeyConfigurationError, "Base64"):
            load_master_key()

    def test_wrong_key_length_fails_safely(self):
        self.master_key_path.write_text(
            base64.b64encode(b"too-short").decode("ascii"),
            encoding="ascii",
        )

        with self.assertRaisesRegex(MasterKeyConfigurationError, "32 bytes"):
            load_master_key()

    def test_environment_variable_takes_precedence(self):
        environment_key = bytes([200]) * 32
        encoded_key = base64.b64encode(environment_key).decode("ascii")

        with mock.patch.dict(os.environ, {"SECUREQR_MASTER_KEY": encoded_key}):
            self.assertEqual(load_master_key(), environment_key)

    def test_environment_key_works_without_a_file(self):
        environment_key = bytes([201]) * 32
        encoded_key = base64.b64encode(environment_key).decode("ascii")
        missing_path = Path(self.temp_directory.name) / "missing" / "master.key"

        with override_settings(SECUREQR_MASTER_KEY_FILE=missing_path):
            with mock.patch.dict(os.environ, {"SECUREQR_MASTER_KEY": encoded_key}):
                self.assertEqual(load_master_key(), environment_key)

    def test_create_key_file_refuses_to_overwrite(self):
        new_path = Path(self.temp_directory.name) / "new" / "master.key"

        with mock.patch.dict(os.environ, {"SECUREQR_MASTER_KEY": ""}):
            created_path = create_master_key_file(new_path)
            first_contents = new_path.read_bytes()

            self.assertEqual(created_path, new_path)
            self.assertEqual(len(base64.b64decode(first_contents)), 32)

            with self.assertRaisesRegex(MasterKeyConfigurationError, "not overwritten"):
                create_master_key_file(new_path)

        self.assertEqual(first_contents, new_path.read_bytes())


class InitMasterKeyCommandTests(MasterKeyTestMixin, TestCase):
    def test_command_creates_key_and_refuses_overwrite(self):
        new_path = Path(self.temp_directory.name) / "command" / "master.key"

        with override_settings(SECUREQR_MASTER_KEY_FILE=new_path):
            with mock.patch.dict(os.environ, {"SECUREQR_MASTER_KEY": ""}):
                output = StringIO()
                call_command("init_master_key", stdout=output)

                self.assertTrue(new_path.is_file())
                self.assertIn("created", output.getvalue().lower())
                self.assertEqual(len(base64.b64decode(new_path.read_bytes())), 32)

                with self.assertRaises(CommandError):
                    call_command("init_master_key", stdout=StringIO())


class CryptoTests(SimpleTestCase):
    def test_encrypt_decrypt_round_trip(self):
        plaintext = json.dumps(
            {"title": "Test", "content": "Unicode secret: नमस्ते 🔐"},
            ensure_ascii=False,
        ).encode("utf-8")

        encrypted = encrypt_payload(plaintext, TEST_TOKEN, TEST_MASTER_KEY)
        decrypted = decrypt_payload(encrypted, TEST_TOKEN, TEST_MASTER_KEY)

        self.assertEqual(decrypted, plaintext)
        self.assertEqual(len(encrypted.nonce), 12)
        self.assertEqual(len(encrypted.key_nonce), 12)
        self.assertEqual(len(encrypted.wrapped_data_key), 48)
        self.assertEqual(len(unwrap_data_key(
            encrypted.wrapped_data_key,
            encrypted.key_nonce,
            TEST_TOKEN,
            TEST_MASTER_KEY,
            encrypted.key_version,
        )), 32)

    def test_each_record_gets_a_different_data_key_and_nonce(self):
        plaintext = b"the same plaintext"
        first = encrypt_payload(plaintext, TEST_TOKEN, TEST_MASTER_KEY)
        second = encrypt_payload(plaintext, TEST_TOKEN, TEST_MASTER_KEY)

        first_data_key = unwrap_data_key(
            first.wrapped_data_key,
            first.key_nonce,
            TEST_TOKEN,
            TEST_MASTER_KEY,
            first.key_version,
        )
        second_data_key = unwrap_data_key(
            second.wrapped_data_key,
            second.key_nonce,
            TEST_TOKEN,
            TEST_MASTER_KEY,
            second.key_version,
        )

        self.assertNotEqual(first_data_key, second_data_key)
        self.assertNotEqual(first.nonce, second.nonce)
        self.assertNotEqual(first.key_nonce, second.key_nonce)
        self.assertNotEqual(first.ciphertext, second.ciphertext)
        self.assertNotEqual(first.wrapped_data_key, second.wrapped_data_key)

    def test_changing_ciphertext_fails_authentication(self):
        encrypted = encrypt_payload(b"protected", TEST_TOKEN, TEST_MASTER_KEY)
        tampered = replace(
            encrypted,
            ciphertext=bytes([encrypted.ciphertext[0] ^ 1]) + encrypted.ciphertext[1:],
        )

        with self.assertRaises(DecryptionError):
            decrypt_payload(tampered, TEST_TOKEN, TEST_MASTER_KEY)

    def test_changing_nonce_fails_authentication(self):
        encrypted = encrypt_payload(b"protected", TEST_TOKEN, TEST_MASTER_KEY)
        tampered = replace(
            encrypted,
            nonce=bytes([encrypted.nonce[0] ^ 1]) + encrypted.nonce[1:],
        )

        with self.assertRaises(DecryptionError):
            decrypt_payload(tampered, TEST_TOKEN, TEST_MASTER_KEY)

    def test_changing_wrapped_data_key_fails_authentication(self):
        encrypted = encrypt_payload(b"protected", TEST_TOKEN, TEST_MASTER_KEY)
        tampered = replace(
            encrypted,
            wrapped_data_key=bytes([encrypted.wrapped_data_key[0] ^ 1])
            + encrypted.wrapped_data_key[1:],
        )

        with self.assertRaises(DecryptionError):
            decrypt_payload(tampered, TEST_TOKEN, TEST_MASTER_KEY)

    def test_wrong_record_token_fails_metadata_authentication(self):
        encrypted = encrypt_payload(b"protected", TEST_TOKEN, TEST_MASTER_KEY)

        with self.assertRaises(DecryptionError):
            decrypt_payload(encrypted, "B" * 43, TEST_MASTER_KEY)

    def test_wrong_master_key_fails(self):
        encrypted = encrypt_payload(b"protected", TEST_TOKEN, TEST_MASTER_KEY)

        with self.assertRaises(DecryptionError):
            decrypt_payload(encrypted, TEST_TOKEN, bytes([99]) * 32)

    def test_malformed_envelope_data_fails_safely(self):
        encrypted = encrypt_payload(b"protected", TEST_TOKEN, TEST_MASTER_KEY)

        malformed_values = (
            replace(encrypted, nonce=b"short"),
            replace(encrypted, ciphertext=b"short"),
            replace(encrypted, wrapped_data_key=b"short"),
        )
        for malformed in malformed_values:
            with self.subTest(malformed=malformed):
                with self.assertRaises(DecryptionError):
                    decrypt_payload(malformed, TEST_TOKEN, TEST_MASTER_KEY)

    def test_invalid_master_key_or_plaintext_is_rejected(self):
        with self.assertRaises(EncryptionError):
            encrypt_payload(b"protected", TEST_TOKEN, b"too-short")
        with self.assertRaises(EncryptionError):
            encrypt_payload("not bytes", TEST_TOKEN, TEST_MASTER_KEY)


@override_settings(SECUREQR_PASSWORD_ITERATIONS=10_000)
class PasswordEnvelopeTests(SimpleTestCase):
    def test_wrap_and_unwrap_round_trip(self):
        key_material = new_password_key(TEST_PASSWORD)
        data_key = bytes(range(DATA_KEY_BYTES))
        wrapped = wrap_data_key_with_password_key(
            key_material, data_key, TEST_TOKEN, "payload"
        )

        unwrapped = unwrap_data_key_with_password(
            TEST_TOKEN,
            "payload",
            TEST_PASSWORD,
            key_material.salt,
            key_material.iterations,
            wrapped.wrapped_data_key,
            wrapped.nonce,
        )

        self.assertEqual(unwrapped, data_key)
        self.assertEqual(len(key_material.salt), 16)
        self.assertEqual(key_material.iterations, 10_000)
        self.assertEqual(
            derive_password_key(
                TEST_PASSWORD, key_material.salt, key_material.iterations
            ),
            key_material.key,
        )

    def test_missing_unlock_data_is_rejected(self):
        with self.assertRaises(PasswordUnlockError):
            unwrap_data_key_with_password(
                TEST_TOKEN, "payload", TEST_PASSWORD, b"", None, b"", b""
            )

    def test_wrong_password_is_rejected(self):
        key_material = new_password_key(TEST_PASSWORD)
        wrapped = wrap_data_key_with_password_key(
            key_material, bytes(range(DATA_KEY_BYTES)), TEST_TOKEN, "payload"
        )

        with self.assertRaises(InvalidPasswordError):
            unwrap_data_key_with_password(
                TEST_TOKEN,
                "payload",
                "not the right password",
                key_material.salt,
                key_material.iterations,
                wrapped.wrapped_data_key,
                wrapped.nonce,
            )

    def test_wrong_record_role_is_rejected(self):
        key_material = new_password_key(TEST_PASSWORD)
        wrapped = wrap_data_key_with_password_key(
            key_material, bytes(range(DATA_KEY_BYTES)), TEST_TOKEN, "payload"
        )

        with self.assertRaises(InvalidPasswordError):
            unwrap_data_key_with_password(
                TEST_TOKEN,
                "image",
                TEST_PASSWORD,
                key_material.salt,
                key_material.iterations,
                wrapped.wrapped_data_key,
                wrapped.nonce,
            )

    def test_tampered_password_wrapper_is_rejected(self):
        key_material = new_password_key(TEST_PASSWORD)
        wrapped = wrap_data_key_with_password_key(
            key_material, bytes(range(DATA_KEY_BYTES)), TEST_TOKEN, "payload"
        )
        tampered = bytes([wrapped.wrapped_data_key[0] ^ 1]) + wrapped.wrapped_data_key[1:]

        with self.assertRaises(InvalidPasswordError):
            unwrap_data_key_with_password(
                TEST_TOKEN,
                "payload",
                TEST_PASSWORD,
                key_material.salt,
                key_material.iterations,
                tampered,
                wrapped.nonce,
            )


class SecureRecordFormTests(SimpleTestCase):
    def setUp(self):
        self.form_data = {
            "title": "Security note",
            "content": "A secret message",
            "source_url": "https://example.com/reference",
            "password": TEST_PASSWORD,
        }

    def test_valid_form(self):
        form = SecureRecordForm(self.form_data)

        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["title"], "Security note")

    def test_content_preserves_internal_whitespace(self):
        secret = "  line one\nline two  "
        form = SecureRecordForm({**self.form_data, "content": secret})

        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["content"], secret)

    def test_blank_content_is_rejected(self):
        form = SecureRecordForm({**self.form_data, "content": "   \n  "})

        self.assertFalse(form.is_valid())
        self.assertIn("content", form.errors)

    def test_short_password_is_rejected(self):
        form = SecureRecordForm({**self.form_data, "password": "short"})

        self.assertFalse(form.is_valid())
        self.assertIn("password", form.errors)

    def test_blank_password_is_rejected(self):
        form = SecureRecordForm({**self.form_data, "password": "        "})

        self.assertFalse(form.is_valid())
        self.assertIn("password", form.errors)

    def test_unlock_form_requires_password(self):
        form = UnlockForm({"password": "   "})

        self.assertFalse(form.is_valid())
        self.assertIn("password", form.errors)

    def test_unsafe_url_scheme_is_rejected(self):
        form = SecureRecordForm(
            {**self.form_data, "source_url": "javascript:alert(1)"}
        )

        self.assertFalse(form.is_valid())
        self.assertIn("source_url", form.errors)

    def test_optional_url_can_be_blank(self):
        form = SecureRecordForm({**self.form_data, "source_url": ""})

        self.assertTrue(form.is_valid(), form.errors)

    def test_valid_image_is_checked_from_file_bytes(self):
        upload = make_image_upload(filename="scan.png", image_format="PNG")
        form = SecureRecordForm(self.form_data, {"image": upload})

        self.assertTrue(form.is_valid(), form.errors)
        self.assertIsNotNone(form.validated_image)
        self.assertEqual(form.validated_image.filename, "scan.png")
        self.assertEqual(form.validated_image.content_type, "image/png")
        self.assertEqual(form.validated_image.image_format, "PNG")
        self.assertEqual(form.validated_image.size, upload.size)

    def test_client_mime_type_is_not_trusted(self):
        upload = SimpleUploadedFile(
            "photo.jpg",
            make_image_bytes("PNG"),
            content_type="image/jpeg",
        )
        form = SecureRecordForm(self.form_data, {"image": upload})

        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.validated_image.image_format, "PNG")
        self.assertEqual(form.validated_image.content_type, "image/png")

    def test_disguised_image_is_rejected(self):
        upload = SimpleUploadedFile(
            "fake.png",
            b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>",
            content_type="image/png",
        )
        form = SecureRecordForm(self.form_data, {"image": upload})

        self.assertFalse(form.is_valid())
        self.assertIn("image", form.errors)
        self.assertIsNone(form.validated_image)
        self.assertIn("valid JPEG, PNG, or WebP", form.errors["image"][0])

    def test_unsupported_image_format_is_rejected(self):
        upload = SimpleUploadedFile(
            "animation.gif",
            make_image_bytes("GIF"),
            content_type="image/gif",
        )
        form = SecureRecordForm(self.form_data, {"image": upload})

        self.assertFalse(form.is_valid())
        self.assertIn("Only JPEG, PNG, and WebP", form.errors["image"][0])

    def test_oversized_image_is_rejected(self):
        upload = SimpleUploadedFile(
            "large.jpg",
            make_image_bytes("JPEG"),
            content_type="image/jpeg",
        )
        upload._size = 11

        with mock.patch("website.forms.MAX_IMAGE_UPLOAD_BYTES", 10):
            form = SecureRecordForm(self.form_data, {"image": upload})
            self.assertFalse(form.is_valid())
            self.assertIn("too large", form.errors["image"][0])


class GeneratorViewTests(MasterKeyTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.title = "Viva access record 84d2"
        self.secret = "Unique secret 9f3c1a7d - do not display"
        self.source_url = "https://example.com/private/84d2"
        self.form_data = {
            "title": self.title,
            "content": self.secret,
            "source_url": self.source_url,
            "password": TEST_PASSWORD,
        }
        self.password = TEST_PASSWORD

    def create_record(self, image=None):
        data = dict(self.form_data)
        if image is not None:
            data["image"] = image
        return self.client.post(reverse("website:generator"), data)

    def decrypt_image(self, record):
        encrypted_image = EncryptedPayload(
            ciphertext=bytes(record.image_ciphertext),
            nonce=bytes(record.image_nonce),
            wrapped_data_key=bytes(record.image_wrapped_data_key),
            key_nonce=bytes(record.image_key_nonce),
            key_version=record.image_key_version,
        )
        return decrypt_payload(encrypted_image, record.token, self.master_key)

    def test_generator_page_loads(self):
        response = self.client.get(reverse("website:generator"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "website/generator.html")
        self.assertContains(response, "id=\"recordForm\"")
        self.assertContains(response, "action=\"/\"")
        self.assertContains(response, "enctype=\"multipart/form-data\"")
        self.assertContains(response, "csrfmiddlewaretoken")
        self.assertContains(response, "data-direct-url=\"http://testserver/\"")
        self.assertContains(response, "Upload / Browse Photos")
        self.assertContains(response, "id=\"photoUploadCard\"")
        self.assertContains(response, "id=\"id_image\"")
        self.assertContains(response, "name=\"image\"")
        self.assertContains(response, "type=\"file\"")
        self.assertContains(response, "id=\"id_password\"")
        self.assertContains(response, "name=\"password\"")
        self.assertContains(response, "Unlock password")
        self.assertContains(response, "Choose Photo")
        self.assertContains(response, "id=\"photoPreview\"")
        self.assertContains(response, "id=\"removePhotoButton\"")
        self.assertEqual(
            response.headers["Content-Security-Policy"],
            "frame-ancestors 'none'",
        )
        self.assertTrue(response.context["encryption_ready"])
        self.assertIsNone(response.context["result"])

    def test_valid_post_encrypts_record_and_builds_qr(self):
        response = self.create_record()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(EncryptedRecord.objects.count(), 1)
        self.assertFalse(response.context["form"].is_bound)

        record = EncryptedRecord.objects.get()
        result = response.context["result"]

        self.assertTrue(is_valid_record_token(record.token))
        self.assertEqual(len(record.token), 43)
        self.assertTrue(result["record_url"].startswith("http://testserver/r/"))
        self.assertTrue(result["qr_data_uri"].startswith("data:image/png;base64,"))
        self.assertEqual(
            result["download_filename"],
            f"secureqr-{record.token}.png",
        )
        self.assertFalse(record.has_image)
        self.assertIsNone(record.image_ciphertext)
        self.assertFalse(result["has_image"])

        self.assertIsNotNone(record.password_salt)
        self.assertIsNotNone(record.password_wrapped_data_key)
        self.assertIsNotNone(record.password_key_nonce)
        self.assertEqual(record.password_iterations, 10_000)

        html = response.content.decode("utf-8")
        self.assertNotIn(self.secret, html)
        self.assertNotIn(self.title, html)
        self.assertNotIn(self.source_url, html)
        self.assertNotIn(self.password, html)

    def test_saved_record_is_internally_decryptable(self):
        response = self.create_record()
        record = EncryptedRecord.objects.get()
        result = response.context["result"]

        encrypted = EncryptedPayload(
            ciphertext=bytes(record.ciphertext),
            nonce=bytes(record.nonce),
            wrapped_data_key=bytes(record.wrapped_data_key),
            key_nonce=bytes(record.key_nonce),
            key_version=record.key_version,
        )
        decrypted = decrypt_payload(encrypted, record.token, self.master_key)
        payload = json.loads(decrypted.decode("utf-8"))

        self.assertEqual(payload["title"], self.title)
        self.assertEqual(payload["content"], self.secret)
        self.assertEqual(payload["url"], self.source_url)
        self.assertEqual(result["record_url"], f"http://testserver/r/{record.token}/")

    def test_image_upload_encrypts_original_bytes_and_metadata(self):
        image_bytes = make_image_bytes("PNG")
        image_upload = SimpleUploadedFile(
            "diagram.png",
            image_bytes,
            content_type="image/png",
        )
        response = self.create_record(image=image_upload)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(EncryptedRecord.objects.count(), 1)
        record = EncryptedRecord.objects.get()
        result = response.context["result"]

        self.assertTrue(record.has_image)
        self.assertTrue(result["has_image"])
        self.assertEqual(self.decrypt_image(record), image_bytes)
        self.assertContains(response, "A photo is encrypted with this record")

        encrypted_text = EncryptedPayload(
            ciphertext=bytes(record.ciphertext),
            nonce=bytes(record.nonce),
            wrapped_data_key=bytes(record.wrapped_data_key),
            key_nonce=bytes(record.key_nonce),
            key_version=record.key_version,
        )
        payload = json.loads(
            decrypt_payload(encrypted_text, record.token, self.master_key).decode("utf-8")
        )
        self.assertEqual(
            payload["image"],
            {
                "filename": "diagram.png",
                "content_type": "image/png",
                "format": "PNG",
                "size": len(image_bytes),
            },
        )

        stored_values = (
            bytes(record.ciphertext),
            bytes(record.image_ciphertext),
            bytes(record.image_nonce),
            bytes(record.image_wrapped_data_key),
            bytes(record.image_key_nonce),
        )
        for stored_value in stored_values:
            self.assertNotIn(image_bytes, stored_value)
            self.assertNotIn(b"diagram.png", stored_value)

    def test_jpeg_png_and_webp_uploads_are_accepted(self):
        uploads = (
            ("photo.jpg", "JPEG", "image/jpeg"),
            ("photo.png", "PNG", "image/png"),
            ("photo.webp", "WEBP", "image/webp"),
        )

        for filename, image_format, content_type in uploads:
            with self.subTest(image_format=image_format):
                image_bytes = make_image_bytes(image_format)
                upload = SimpleUploadedFile(
                    filename,
                    image_bytes,
                    content_type=content_type,
                )
                response = self.create_record(image=upload)

                self.assertEqual(response.status_code, 200)
                record = EncryptedRecord.objects.latest("id")
                self.assertTrue(record.has_image)
                self.assertEqual(self.decrypt_image(record), image_bytes)
                encrypted_text = EncryptedPayload(
                    ciphertext=bytes(record.ciphertext),
                    nonce=bytes(record.nonce),
                    wrapped_data_key=bytes(record.wrapped_data_key),
                    key_nonce=bytes(record.key_nonce),
                    key_version=record.key_version,
                )
                payload = json.loads(
                    decrypt_payload(
                        encrypted_text,
                        record.token,
                        self.master_key,
                    ).decode("utf-8")
                )
                self.assertEqual(payload["image"]["format"], image_format)
                self.assertEqual(payload["image"]["content_type"], content_type)

    def test_invalid_image_upload_creates_no_record(self):
        upload = SimpleUploadedFile(
            "fake.jpg",
            b"this is not an image",
            content_type="image/jpeg",
        )
        response = self.create_record(image=upload)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(EncryptedRecord.objects.count(), 0)
        self.assertTrue(response.context["form_errors"])
        self.assertIn("Photo", " ".join(response.context["form_errors"]))
        self.assertNotIn(self.secret, response.content.decode("utf-8"))

    def test_oversized_image_upload_creates_no_record(self):
        upload = SimpleUploadedFile(
            "large.jpg",
            b"x" * 11,
            content_type="image/jpeg",
        )

        with mock.patch("website.forms.MAX_IMAGE_UPLOAD_BYTES", 10):
            response = self.create_record(image=upload)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(EncryptedRecord.objects.count(), 0)
        self.assertIn("too large", " ".join(response.context["form_errors"]))

    def test_record_detail_does_not_render_image_ciphertext(self):
        image_bytes = make_image_bytes("PNG")
        upload = SimpleUploadedFile("diagram.png", image_bytes, content_type="image/png")
        response = self.create_record(image=upload)
        record = EncryptedRecord.objects.get()
        detail_response = self.client.get(response.context["result"]["record_url"])
        detail_html = detail_response.content.decode("utf-8")

        self.assertEqual(detail_response.status_code, 200)
        self.assertTrue(detail_response.context["has_image"])
        self.assertIn("Encrypted photo attached", detail_html)
        self.assertNotIn(
            base64.b64encode(bytes(record.image_ciphertext)).decode("ascii"),
            detail_html,
        )
        self.assertNotIn(image_bytes, detail_response.content)

    def test_database_contains_no_plaintext_fields(self):
        self.create_record()
        record = EncryptedRecord.objects.get()
        stored_values = (
            bytes(record.ciphertext),
            bytes(record.nonce),
            bytes(record.wrapped_data_key),
            bytes(record.key_nonce),
            bytes(record.password_salt),
            bytes(record.password_wrapped_data_key),
            bytes(record.password_key_nonce),
            record.token.encode("utf-8"),
        )

        for stored_value in stored_values:
            for sensitive in (self.title, self.secret, self.source_url, self.password):
                self.assertNotIn(sensitive.encode("utf-8"), stored_value)

        field_names = {field.name for field in EncryptedRecord._meta.get_fields()}
        self.assertNotIn("title", field_names)
        self.assertNotIn("content", field_names)
        self.assertNotIn("source_url", field_names)
        self.assertNotIn("password", field_names)

    def test_qr_content_is_only_the_record_url(self):
        original_add_data = qrcode.QRCode.add_data
        captured = {}

        def capture_data(qr_instance, data, *args, **kwargs):
            captured["data"] = data
            return original_add_data(qr_instance, data, *args, **kwargs)

        with mock.patch.object(qrcode.QRCode, "add_data", capture_data):
            response = self.create_record()

        result = response.context["result"]
        record = EncryptedRecord.objects.get()
        qr_content = captured["data"]

        self.assertEqual(qr_content, result["record_url"])
        self.assertEqual(urlparse(qr_content).path, f"/r/{record.token}/")
        for sensitive in (self.title, self.secret, self.source_url, self.password):
            self.assertNotIn(sensitive, qr_content)

        master_key_b64 = base64.b64encode(self.master_key).decode("ascii")
        self.assertNotIn(master_key_b64, qr_content)
        self.assertNotIn(
            base64.b64encode(bytes(record.wrapped_data_key)).decode("ascii"),
            qr_content,
        )

    def test_two_records_get_different_tokens(self):
        self.create_record()
        self.create_record()

        records = list(EncryptedRecord.objects.order_by("id"))
        self.assertEqual(len(records), 2)
        self.assertNotEqual(records[0].token, records[1].token)

    def test_validation_error_clears_secret_and_creates_no_record(self):
        response = self.client.post(
            reverse("website:generator"),
            {
                "title": "",
                "content": self.secret,
                "source_url": self.source_url,
                "password": self.password,
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(EncryptedRecord.objects.count(), 0)
        self.assertFalse(response.context["form"].is_bound)
        self.assertTrue(response.context["form_errors"])
        html = response.content.decode("utf-8")
        self.assertNotIn(self.secret, html)
        self.assertNotIn(self.source_url, html)
        self.assertNotIn(self.password, html)

    def test_missing_master_key_fails_safely(self):
        missing_path = Path(self.temp_directory.name) / "missing" / "master.key"

        with override_settings(SECUREQR_MASTER_KEY_FILE=missing_path):
            with self.assertLogs("website.views", level="ERROR") as captured:
                response = self.create_record()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(EncryptedRecord.objects.count(), 0)
        self.assertFalse(response.context["encryption_ready"])
        self.assertContains(response, "python manage.py init_master_key")
        self.assertNotIn(self.secret, response.content.decode("utf-8"))
        self.assertNotIn(self.secret, "\n".join(captured.output))

    @override_settings(DEBUG=True)
    def test_development_error_is_displayed_when_save_fails(self):
        error = OperationalError(
            "table website_encryptedrecord has no column named image_ciphertext"
        )

        with mock.patch("website.models.EncryptedRecord.save", side_effect=error):
            with self.assertLogs("website.views", level="ERROR") as captured:
                response = self.create_record()

        html = response.content.decode("utf-8")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(EncryptedRecord.objects.count(), 0)
        self.assertTrue(response.context["debug_mode"])
        self.assertContains(response, "data-dev-error=")
        self.assertContains(response, "no column named image_ciphertext")
        self.assertContains(response, "python manage.py migrate")
        self.assertIn("OperationalError", "\n".join(captured.output))
        self.assertNotIn(self.secret, html)
        self.assertNotIn(self.title, html)

    def test_secret_is_not_logged_on_success(self):
        with self.assertLogs("website", level="DEBUG") as captured:
            logging.getLogger("website").debug("test marker")
            self.create_record()

        logs = "\n".join(captured.output)
        self.assertNotIn(self.secret, logs)
        self.assertNotIn(self.title, logs)
        self.assertNotIn(self.source_url, logs)
        self.assertNotIn(self.password, logs)

    def test_csrf_protection_rejects_post_without_token(self):
        csrf_client = Client(enforce_csrf_checks=True)

        response = csrf_client.post(reverse("website:generator"), self.form_data)

        self.assertEqual(response.status_code, 403)
        self.assertEqual(EncryptedRecord.objects.count(), 0)

    def test_referrer_policy_preserves_origin_for_native_form_posts(self):
        response = self.client.get(reverse("website:generator"))

        self.assertEqual(response.headers["Referrer-Policy"], "strict-origin")
        self.assertNotEqual(response.headers["Referrer-Policy"], "no-referrer")

    def test_csrf_accepts_same_origin_post_with_valid_token(self):
        csrf_client = Client(enforce_csrf_checks=True)
        get_response = csrf_client.get(reverse("website:generator"))
        csrf_token = get_response.cookies["csrftoken"].value

        response = csrf_client.post(
            reverse("website:generator"),
            {**self.form_data, "csrfmiddlewaretoken": csrf_token},
            HTTP_ORIGIN="http://testserver",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(EncryptedRecord.objects.count(), 1)

    def test_csrf_rejects_null_origin_even_with_valid_token(self):
        csrf_client = Client(enforce_csrf_checks=True)
        get_response = csrf_client.get(reverse("website:generator"))
        csrf_token = get_response.cookies["csrftoken"].value

        response = csrf_client.post(
            reverse("website:generator"),
            {**self.form_data, "csrfmiddlewaretoken": csrf_token},
            HTTP_ORIGIN="null",
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(EncryptedRecord.objects.count(), 0)

    @override_settings(DEBUG=True)
    def test_csrf_diagnostics_log_origin_without_secrets(self):
        csrf_client = Client(enforce_csrf_checks=True)
        get_response = csrf_client.get(reverse("website:generator"))
        csrf_token = get_response.cookies["csrftoken"].value

        with self.assertLogs("website.csrf_diagnostics", level="WARNING") as captured:
            response = csrf_client.post(
                reverse("website:generator"),
                {**self.form_data, "csrfmiddlewaretoken": csrf_token},
                HTTP_ORIGIN="null",
                HTTP_REFERER="file:///D:/preview/generator.html",
            )

        logs = "\n".join(captured.output)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(EncryptedRecord.objects.count(), 0)
        self.assertIn("origin=null", logs)
        self.assertIn("has_csrf_cookie=True", logs)
        self.assertIn("response_status=403", logs)
        self.assertNotIn(self.secret, logs)
        self.assertNotIn(self.title, logs)
        self.assertNotIn(self.source_url, logs)
        self.assertNotIn(self.password, logs)
        self.assertNotIn(csrf_token, logs)

    def test_record_detail_shows_password_form_and_no_plaintext(self):
        response = self.create_record()
        record = EncryptedRecord.objects.get()
        record_url = response.context["result"]["record_url"]

        detail_response = self.client.get(record_url)
        detail_html = detail_response.content.decode("utf-8")

        self.assertEqual(detail_response.status_code, 200)
        self.assertTemplateUsed(detail_response, "website/record_detail.html")
        self.assertIn(
            base64.b64encode(bytes(record.ciphertext)).decode("ascii"),
            detail_html,
        )
        self.assertIn(record.token, detail_html)
        self.assertIn("Enter the unlock password", detail_html)
        self.assertIn("name=\"password\"", detail_html)
        self.assertIn("csrfmiddlewaretoken", detail_html)
        self.assertEqual(detail_response.headers["Cache-Control"], "no-store")
        for sensitive in (self.secret, self.title, self.source_url, self.password):
            self.assertNotIn(sensitive, detail_html)
        for value in (
            record.wrapped_data_key,
            record.password_wrapped_data_key,
            self.master_key,
        ):
            self.assertNotIn(
                base64.b64encode(bytes(value)).decode("ascii"),
                detail_html,
            )

    def test_unlock_requires_correct_password_and_displays_record(self):
        image_bytes = make_image_bytes("PNG")
        upload = SimpleUploadedFile(
            "diagram.png",
            image_bytes,
            content_type="image/png",
        )
        self.create_record(image=upload)
        record = EncryptedRecord.objects.get()
        path = reverse("website:record_detail", kwargs={"token": record.token})
        image_b64 = base64.b64encode(image_bytes).decode("ascii")

        wrong = self.client.post(path, {"password": "definitely not the password"})
        wrong_html = wrong.content.decode("utf-8")

        self.assertEqual(wrong.status_code, 200)
        self.assertTemplateUsed(wrong, "website/record_detail.html")
        self.assertIn("incorrect", wrong_html.lower())
        self.assertEqual(wrong.headers["Cache-Control"], "no-store")
        for sensitive in (
            self.title,
            self.secret,
            self.source_url,
            self.password,
            image_b64,
        ):
            self.assertNotIn(sensitive, wrong_html)

        correct = self.client.post(path, {"password": self.password})
        unlocked_html = correct.content.decode("utf-8")

        self.assertEqual(correct.status_code, 200)
        self.assertTemplateUsed(correct, "website/record_unlocked.html")
        self.assertEqual(correct.headers["Cache-Control"], "no-store")
        self.assertIn(self.title, unlocked_html)
        self.assertIn(self.secret, unlocked_html)
        self.assertIn(self.source_url, unlocked_html)
        self.assertIn("data:image/png;base64," + image_b64, unlocked_html)
        self.assertIn("diagram.png", unlocked_html)
        self.assertNotIn(self.password, unlocked_html)

        data_key = unwrap_data_key(
            bytes(record.wrapped_data_key),
            bytes(record.key_nonce),
            record.token,
            self.master_key,
            record.key_version,
        )
        for value in (
            self.master_key,
            data_key,
            record.wrapped_data_key,
            record.password_wrapped_data_key,
            record.password_salt,
            record.password_key_nonce,
            record.image_wrapped_data_key,
            record.image_password_wrapped_data_key,
            record.image_password_key_nonce,
        ):
            self.assertNotIn(
                base64.b64encode(bytes(value)).decode("ascii"),
                unlocked_html,
            )

    def test_unlock_requires_csrf_token(self):
        self.create_record()
        record = EncryptedRecord.objects.get()
        path = reverse("website:record_detail", kwargs={"token": record.token})
        csrf_client = Client(enforce_csrf_checks=True)
        get_response = csrf_client.get(path)
        csrf_token = get_response.cookies["csrftoken"].value

        rejected = csrf_client.post(path, {"password": self.password})
        self.assertEqual(rejected.status_code, 403)

        accepted = csrf_client.post(
            path,
            {"password": self.password, "csrfmiddlewaretoken": csrf_token},
            HTTP_ORIGIN="http://testserver",
        )
        self.assertEqual(accepted.status_code, 200)
        self.assertIn(self.secret, accepted.content.decode("utf-8"))

    def test_missing_or_malformed_record_returns_404(self):
        missing_response = self.client.get(
            reverse("website:record_detail", kwargs={"token": "A" * 43})
        )
        short_response = self.client.get(
            reverse("website:record_detail", kwargs={"token": "short"})
        )
        bad_chars_response = self.client.get(
            reverse("website:record_detail", kwargs={"token": "!" * 43})
        )

        self.assertEqual(missing_response.status_code, 404)
        self.assertEqual(short_response.status_code, 404)
        self.assertEqual(bad_chars_response.status_code, 404)

    def test_record_detail_rejects_unsupported_methods(self):
        path = reverse("website:record_detail", kwargs={"token": "A" * 43})

        for method in ("put", "patch", "delete"):
            with self.subTest(method=method):
                response = getattr(self.client, method)(path)
                self.assertEqual(response.status_code, 405)

    def test_only_expected_routes_exist(self):
        for path in ("/admin/", "/issue/", "/verify/", "/decrypt/"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)
