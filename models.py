from django.db import models


class EncryptedRecord(models.Model):
    """An encrypted envelope. No plaintext record fields are stored here."""

    token = models.CharField(max_length=64, unique=True)
    ciphertext = models.BinaryField()
    nonce = models.BinaryField(max_length=12)
    wrapped_data_key = models.BinaryField(max_length=48)
    key_nonce = models.BinaryField(max_length=12)
    key_version = models.PositiveSmallIntegerField(default=1)
    password_salt = models.BinaryField(max_length=16, null=True, blank=True)
    password_wrapped_data_key = models.BinaryField(max_length=48, null=True, blank=True)
    password_key_nonce = models.BinaryField(max_length=12, null=True, blank=True)
    password_iterations = models.PositiveIntegerField(null=True, blank=True)
    image_ciphertext = models.BinaryField(null=True, blank=True)
    image_nonce = models.BinaryField(max_length=12, null=True, blank=True)
    image_wrapped_data_key = models.BinaryField(max_length=48, null=True, blank=True)
    image_key_nonce = models.BinaryField(max_length=12, null=True, blank=True)
    image_key_version = models.PositiveSmallIntegerField(null=True, blank=True)
    image_password_wrapped_data_key = models.BinaryField(
        max_length=48, null=True, blank=True
    )
    image_password_key_nonce = models.BinaryField(max_length=12, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    @property
    def has_image(self):
        return self.image_ciphertext is not None

    def __str__(self):
        return f"Encrypted record {self.token[:8]}..."
