import os
from dataclasses import dataclass
from io import BytesIO

from django import forms
from django.core.validators import URLValidator
from PIL import Image, UnidentifiedImageError

MAX_IMAGE_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_IMAGE_PIXELS = 30_000_000
ALLOWED_IMAGE_FORMATS = {
    "JPEG": "image/jpeg",
    "PNG": "image/png",
    "WEBP": "image/webp",
}
IMAGE_ACCEPT_ATTRIBUTE = ".jpg,.jpeg,.png,.webp,image/jpeg,image/png,image/webp"


def _safe_filename(name):
    base_name = os.path.basename((name or "").replace("\\", "/")).strip()
    printable = "".join(character for character in base_name if character.isprintable())
    return printable[:255] or "photo"


@dataclass(frozen=True)
class ValidatedImage:
    data: bytes
    filename: str
    content_type: str
    image_format: str
    size: int

    @property
    def metadata(self):
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "format": self.image_format,
            "size": self.size,
        }


class SecureRecordForm(forms.Form):
    """Validate input before it is encrypted. It never saves plaintext."""

    title = forms.CharField(
        label="Record title",
        max_length=120,
        min_length=2,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "e.g. Lab access note",
                "autocomplete": "off",
            }
        ),
    )
    content = forms.CharField(
        label="Secret content",
        max_length=5000,
        strip=False,
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "rows": 6,
                "placeholder": "Enter the message, statement, note, or password to encrypt.",
                "autocomplete": "off",
                "autocapitalize": "off",
                "spellcheck": "false",
            }
        ),
    )
    source_url = forms.CharField(
        label="Reference URL (optional)",
        max_length=500,
        required=False,
        validators=[
            URLValidator(
                schemes=["http", "https"],
                message="Enter a valid http:// or https:// URL.",
            )
        ],
        widget=forms.URLInput(
            attrs={
                "class": "form-control",
                "placeholder": "https://example.com/reference",
                "autocomplete": "off",
            }
        ),
    )
    password = forms.CharField(
        label="Unlock password",
        min_length=8,
        max_length=128,
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "placeholder": "At least 8 characters",
                "autocomplete": "new-password",
            }
        ),
    )
    image = forms.FileField(
        label="Photo",
        required=False,
        widget=forms.FileInput(
            attrs={
                "class": "photo-file-input",
                "accept": IMAGE_ACCEPT_ATTRIBUTE,
            }
        ),
    )

    validated_image = None

    def clean_title(self):
        title = self.cleaned_data["title"].strip()
        if len(title) < 2:
            raise forms.ValidationError("Enter a title with at least 2 characters.")
        return title

    def clean_content(self):
        content = self.cleaned_data["content"]
        if not content.strip():
            raise forms.ValidationError("Enter the content you want to encrypt.")
        # Return the original value so intentional leading/trailing spaces in a
        # password or note survive encryption.
        return content

    def clean_source_url(self):
        return self.cleaned_data["source_url"].strip()

    def clean_password(self):
        password = self.cleaned_data["password"]
        if not password.strip():
            raise forms.ValidationError("Enter a password for this record.")
        return password

    def clean_image(self):
        uploaded = self.cleaned_data.get("image")
        if not uploaded:
            return None

        uploaded_size = getattr(uploaded, "_size", None)
        if uploaded_size is None:
            uploaded_size = getattr(uploaded, "size", None)
        if uploaded_size is not None and uploaded_size <= 0:
            raise forms.ValidationError("The selected image is empty.")
        if uploaded_size is not None and uploaded_size > MAX_IMAGE_UPLOAD_BYTES:
            raise forms.ValidationError(
                "The selected image is too large. The maximum size is 5 MB."
            )

        data = uploaded.read(MAX_IMAGE_UPLOAD_BYTES + 1)
        uploaded.seek(0)
        if not data:
            raise forms.ValidationError("The selected image is empty.")
        if len(data) > MAX_IMAGE_UPLOAD_BYTES:
            raise forms.ValidationError(
                "The selected image is too large. The maximum size is 5 MB."
            )
        if uploaded_size is not None and uploaded_size > MAX_IMAGE_UPLOAD_BYTES:
            raise forms.ValidationError(
                "The selected image is too large. The maximum size is 5 MB."
            )

        try:
            with Image.open(BytesIO(data)) as image:
                image_format = (image.format or "").upper()
                if image_format not in ALLOWED_IMAGE_FORMATS:
                    raise forms.ValidationError(
                        "Only JPEG, PNG, and WebP images are accepted."
                    )

                width, height = image.size
                if width <= 0 or height <= 0:
                    raise forms.ValidationError("The selected image has invalid dimensions.")
                if width * height > MAX_IMAGE_PIXELS:
                    raise forms.ValidationError(
                        "The selected image has too many pixels. Use an image under 30 megapixels."
                    )

                image.verify()
        except forms.ValidationError:
            raise
        except (
            UnidentifiedImageError,
            Image.DecompressionBombError,
            OSError,
            ValueError,
            SyntaxError,
        ):
            raise forms.ValidationError(
                "The selected file is not a valid JPEG, PNG, or WebP image."
            ) from None

        self.validated_image = ValidatedImage(
            data=data,
            filename=_safe_filename(uploaded.name),
            content_type=ALLOWED_IMAGE_FORMATS[image_format],
            image_format=image_format,
            size=len(data),
        )
        return uploaded


class UnlockForm(forms.Form):
    """Collect the password needed to unlock an encrypted record."""

    password = forms.CharField(
        label="Unlock password",
        max_length=128,
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "placeholder": "Enter the record password",
                "autocomplete": "current-password",
            }
        ),
    )

    def clean_password(self):
        password = self.cleaned_data["password"]
        if not password.strip():
            raise forms.ValidationError("Enter the record password.")
        return password
