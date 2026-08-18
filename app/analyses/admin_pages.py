from urllib.parse import urljoin, urlparse
from app.services.target_safety import safe_head

COMMON_ADMIN_PATHS = [
    '/admin', '/administrator', '/wp-admin', '/user/login', '/admin/login', '/manage', '/cms', '/login']


def analyze_admin_pages(url, paths=COMMON_ADMIN_PATHS):
    """Check a small list of common admin paths using HEAD to avoid downloading pages.

    Returns list of discovered paths (status 200 or 401/403 might indicate presence).
    """
    try:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        found = []
        for p in paths:
            try:
                full = urljoin(base, p)
                resp = safe_head(full, timeout=6)
                if resp.status_code == 200:
                    found.append({'path': p, 'url': full, 'status': resp.status_code})
                elif resp.status_code in (401, 403):
                    found.append({'path': p, 'url': full, 'status': resp.status_code})
            except Exception:
                continue
        return {'status': 'ok', 'found': found}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}
