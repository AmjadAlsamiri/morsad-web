from urllib.parse import urlparse
from app.services.target_safety import safe_get


def analyze_https(url):
    """Check whether the site enforces HTTPS and whether HTTPS is available.

    Returns dict with scheme, redirects_to_https, hsts_present (if header present handled elsewhere), and https_available.
    """
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme or 'http'
        try:
            resp = safe_get(url, timeout=10)
            final_scheme = urlparse(resp.url).scheme
            redirects_to_https = (final_scheme == 'https')
            https_available = False
            try:
                https_url = 'https://' + parsed.netloc + parsed.path
                r2 = safe_get(https_url, timeout=8)
                https_available = (r2.status_code < 400)
            except Exception:
                https_available = False

            return {'status': 'ok', 'scheme': scheme, 'redirects_to_https': redirects_to_https, 'https_available': https_available}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}
