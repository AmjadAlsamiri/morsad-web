from app.services.target_safety import safe_get


def analyze_headers(url):
    """Fetch the URL and check for common security headers.

    Returns a dict with status, headers, checks, and http_status.
    """
    try:
        resp = safe_get(url, timeout=10)
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        checks = {}
        checks['Strict-Transport-Security'] = 'strict-transport-security' in hdrs
        checks['Content-Security-Policy'] = 'content-security-policy' in hdrs
        checks['X-Frame-Options'] = 'x-frame-options' in hdrs
        checks['X-Content-Type-Options'] = 'x-content-type-options' in hdrs
        checks['Referrer-Policy'] = 'referrer-policy' in hdrs
        checks['Permissions-Policy'] = 'permissions-policy' in hdrs or 'x-permitted-cross-domain-policies' in hdrs
        csp = hdrs.get('content-security-policy', '').lower()
        checks['CSP avoids unsafe directives'] = bool(csp) and "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp
        checks['CORS wildcard not present'] = hdrs.get('access-control-allow-origin', '').strip() != '*'
        checks['Cross-origin isolation policy'] = ('cross-origin-opener-policy' in hdrs and 'cross-origin-resource-policy' in hdrs)
        hsts = hdrs.get('strict-transport-security', '')
        max_age = None
        if 'max-age=' in hsts.lower():
            try:
                max_age = int(hsts.lower().split('max-age=', 1)[1].split(';', 1)[0].strip())
            except ValueError:
                pass
        return {'status': 'ok', 'headers': hdrs, 'checks': checks, 'http_status': resp.status_code,
                'profile': {'hsts_max_age': max_age,
                            'csp_uses_unsafe_directives': "'unsafe-inline'" in csp or "'unsafe-eval'" in csp,
                            'cors_wildcard': hdrs.get('access-control-allow-origin', '').strip() == '*'}}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}
