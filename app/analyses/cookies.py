from app.services.target_safety import safe_get


def analyze_cookies(url):
    """Fetch the URL and inspect Set-Cookie headers for Secure and HttpOnly flags.

    Returns dict with cookies list and summary checks.
    """
    try:
        resp = safe_get(url, timeout=10)
        raw = resp.headers.get('set-cookie')
        cookies = []
        checks = {'has_cookies': False, 'all_secure': True, 'all_httponly': True, 'all_samesite': True}
        try:
            headers = resp.raw.headers.get_all('Set-Cookie')
        except Exception:
            headers = [raw] if raw else []

        for h in headers:
            if not h:
                continue
            checks['has_cookies'] = True
            cookie = {'raw': h}
            lower = h.lower()
            cookie['secure'] = 'secure' in lower
            cookie['httponly'] = 'httponly' in lower
            cookie['samesite'] = 'samesite=' in lower
            if not cookie['secure']:
                checks['all_secure'] = False
            if not cookie['httponly']:
                checks['all_httponly'] = False
            if not cookie['samesite']:
                checks['all_samesite'] = False
            cookies.append(cookie)

        return {'status': 'ok', 'cookies': cookies, 'checks': checks}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}
