from urllib.parse import urljoin, urlparse

from app.services.target_safety import safe_get


def analyze_security_txt(url):
    """Check whether the site publishes a security contact disclosure file."""
    try:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        response = safe_get(urljoin(base, '/.well-known/security.txt'), timeout=8)
        if response.status_code != 200:
            return {'status': 'ok', 'found': False, 'http_status': response.status_code}
        lines = [line.strip() for line in response.text.splitlines()]
        has_contact = any(line.lower().startswith('contact:') for line in lines)
        has_expires = any(line.lower().startswith('expires:') for line in lines)
        return {'status': 'ok', 'found': True, 'has_contact': has_contact, 'has_expires': has_expires}
    except Exception as exc:
        return {'status': 'error', 'error': str(exc)}
