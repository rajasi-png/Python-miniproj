import logging

from django.conf import settings
from django.db import OperationalError
from django.http import Http404
from django.shortcuts import get_object_or_404, render
from django.views.decorators.http import require_http_methods

from .crypto import ALGORITHM, DecryptionError
from .forms import MAX_IMAGE_UPLOAD_BYTES, SecureRecordForm, UnlockForm
from .key_management import (
    MasterKeyConfigurationError,
    load_master_key,
    master_key_is_configured,
)
from .models import EncryptedRecord
from .services import (
    build_encrypted_record,
    build_record_url,
    bytes_to_base64,
    generate_qr_png,
    is_valid_record_token,
    png_data_uri,
    unlock_record,
)

logger = logging.getLogger(__name__)

MASTER_KEY_SETUP_MESSAGE = (
    "Encryption is not configured on this server. Run "
    "python manage.py init_master_key in the project terminal, then reload this page."
)


def _form_error_messages(form):
    messages = []
    for field_name, errors in form.errors.items():
        if field_name == "__all__":
            label = "Form"
        else:
            label = form.fields[field_name].label
        for error in errors:
            messages.append(f"{label}: {error}")
    return messages


def _no_store(response):
    response["Cache-Control"] = "no-store"
    return response


def _development_error_detail(exc):
    message = " ".join(str(exc).split())
    detail = f"{type(exc).__module__}.{type(exc).__name__}: {message}"
    lowered = message.lower()
    if isinstance(exc, OperationalError) and (
        "no column" in lowered or "no such column" in lowered
    ):
        detail += " Run python manage.py migrate to update the database schema."
    return detail


@require_http_methods(["GET", "POST"])
def generator(request):
    """Create an encrypted record and return a QR code for its public URL."""
    form = SecureRecordForm()
    result = None
    form_errors = []
    status_message = ""
    status_type = ""
    dev_error = None
    encryption_ready = master_key_is_configured()

    if request.method == "POST":
        submitted_form = SecureRecordForm(request.POST, request.FILES)

        if submitted_form.is_valid():
            try:
                master_key = load_master_key()
                validated_image = submitted_form.validated_image
                record = build_encrypted_record(
                    title=submitted_form.cleaned_data["title"],
                    content=submitted_form.cleaned_data["content"],
                    source_url=submitted_form.cleaned_data["source_url"],
                    master_key=master_key,
                    password=submitted_form.cleaned_data["password"],
                    image_bytes=validated_image.data if validated_image else None,
                    image_metadata=validated_image.metadata if validated_image else None,
                )

                # Generate the QR before saving so a QR error cannot leave an
                # unreachable record in the database.
                record_url = build_record_url(request, record)
                qr_png = generate_qr_png(record_url)
                record.save()

                result = {
                    "record_url": record_url,
                    "qr_data_uri": png_data_uri(qr_png),
                    "download_filename": f"secureqr-{record.token}.png",
                    "has_image": record.has_image,
                }
                status_type = "success"
                if record.has_image:
                    status_message = (
                        "Record and photo encrypted, then QR code generated. The QR "
                        "contains only the random record URL."
                    )
                else:
                    status_message = (
                        "Record encrypted and QR code generated. The QR contains only "
                        "the random record URL."
                    )
            except MasterKeyConfigurationError:
                logger.error("SecureQR master key is not configured.")
                encryption_ready = False
                status_type = "danger"
                status_message = MASTER_KEY_SETUP_MESSAGE
            except Exception as exc:
                logger.exception("Encrypted record creation failed.")
                status_type = "danger"
                if settings.DEBUG:
                    dev_error = _development_error_detail(exc)
                    status_message = (
                        "The record could not be encrypted or saved. "
                        "Development error: " + dev_error
                    )
                else:
                    status_message = (
                        "The record could not be encrypted or saved. Please try again."
                    )
        else:
            # Never re-render submitted values: a validation error must not echo
            # the secret or other user content back into the HTML page.
            form_errors = _form_error_messages(submitted_form)
            status_type = "danger"
            status_message = (
                "Please correct the errors below. The form was cleared for privacy."
            )

    return render(
        request,
        "website/generator.html",
        {
            "form": form,
            "form_errors": form_errors,
            "result": result,
            "status_message": status_message,
            "status_type": status_type,
            "dev_error": dev_error,
            "debug_mode": settings.DEBUG,
            "encryption_ready": encryption_ready,
            "max_image_upload_bytes": MAX_IMAGE_UPLOAD_BYTES,
        },
    )


@require_http_methods(["GET", "POST"])
def record_detail(request, token):
    """Require a password, then decrypt and display the record for this response."""
    if not is_valid_record_token(token):
        raise Http404("Record not found.")

    record = get_object_or_404(EncryptedRecord, token=token)
    unlock_form = UnlockForm(request.POST) if request.method == "POST" else UnlockForm()
    unlock_error = None
    dev_error = None

    context = {
        "record": record,
        "algorithm": ALGORITHM,
        "ciphertext_b64": bytes_to_base64(record.ciphertext),
        "nonce_b64": bytes_to_base64(record.nonce),
        "has_image": record.has_image,
        "debug_mode": settings.DEBUG,
    }

    if request.method == "POST" and unlock_form.is_valid():
        try:
            decrypted = unlock_record(record, unlock_form.cleaned_data["password"])
        except DecryptionError as exc:
            logger.warning(
                "Password unlock failed for record %s: %s",
                record.token,
                type(exc).__name__,
            )
            unlock_error = (
                "The password is incorrect or this record could not be unlocked."
            )
        except Exception as exc:
            logger.exception("Record unlock failed.")
            unlock_error = "The record could not be unlocked."
            if settings.DEBUG:
                dev_error = _development_error_detail(exc)
                unlock_error += " Development error: " + dev_error
        else:
            context["decrypted"] = decrypted
            return _no_store(render(request, "website/record_unlocked.html", context))

    context["unlock_form"] = unlock_form
    context["unlock_error"] = unlock_error
    context["dev_error"] = dev_error
    return _no_store(render(request, "website/record_detail.html", context))
