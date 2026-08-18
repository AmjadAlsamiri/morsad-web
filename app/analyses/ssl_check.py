from urllib.parse import urlparse
import ssl, socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import datetime
from app.services.target_safety import assert_public_host


def analyze_ssl(url):
    """Retrieve the server TLS certificate and perform basic checks.

    Returns dict with status and certificate details or error.
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        assert_public_host(host)
        port = parsed.port or (443 if parsed.scheme == 'https' else 443)

        pem = ssl.get_server_certificate((host, port))
        cert = x509.load_pem_x509_certificate(pem.encode(), default_backend())
        not_before = cert.not_valid_before
        not_after = cert.not_valid_after
        now = datetime.datetime.utcnow()
        valid = (not_before <= now <= not_after)
        days_remaining = (not_after - now).days
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        san = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san = ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            san = []

        public_key = cert.public_key()
        key_size = getattr(public_key, 'key_size', None)

        return {
            'status': 'ok',
            'valid': valid,
            'not_before': not_before.isoformat(),
            'not_after': not_after.isoformat(),
            'days_remaining': days_remaining,
            'public_key_size': key_size,
            'subject': subject,
            'issuer': issuer,
            'san': san
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}
