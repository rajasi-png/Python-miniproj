import logging
import re
from urllib.parse import urlsplit, urlunsplit

from django.conf import settings

logger = logging.getLogger("website.csrf_diagnostics")

RECORD_TOKEN_PATH = re.compile(r"/r/[A-Za-z0-9_-]{43}/")


class ContentSecurityPolicyMiddleware:
    """Prevent SecureQR pages from being embedded in previews or frames."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
        return response


def _safe_url(value):
    """Remove query strings and redact record tokens from logged URLs."""
    if not value:
        return value
    try:
        parts = urlsplit(value)
    except ValueError:
        return "[unparseable]"
    path = RECORD_TOKEN_PATH.sub("/r/[redacted]/", parts.path)
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


class CSRFDiagnosticsMiddleware:
    """Development-only, non-sensitive diagnostics for unsafe requests.

    This runs before CsrfViewMiddleware, so it also records POST requests that
    Django rejects with 403. It never logs request bodies, cookies, tokens, or
    secret form values.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if settings.DEBUG and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            csrf_cookie_name = settings.CSRF_COOKIE_NAME
            logger.warning(
                "CSRF diagnostics: method=%s path=%s origin=%s referer=%s "
                "content_type=%s has_csrf_cookie=%s host=%s "
                "sec_fetch_dest=%s sec_fetch_site=%s sec_fetch_mode=%s",
                request.method,
                _safe_url(request.path),
                request.META.get("HTTP_ORIGIN", ""),
                _safe_url(request.META.get("HTTP_REFERER", "")),
                request.META.get("CONTENT_TYPE", ""),
                bool(request.COOKIES.get(csrf_cookie_name)),
                request.get_host(),
                request.META.get("HTTP_SEC_FETCH_DEST", ""),
                request.META.get("HTTP_SEC_FETCH_SITE", ""),
                request.META.get("HTTP_SEC_FETCH_MODE", ""),
            )

        response = self.get_response(request)

        if settings.DEBUG and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            logger.warning(
                "CSRF diagnostics: method=%s path=%s response_status=%s",
                request.method,
                _safe_url(request.path),
                response.status_code,
            )

        return response
