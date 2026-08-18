def compute_score(headers_result, ssl_result, https_result=None, cookies_result=None):
    total_checks = 0
    passed = 0
    details = []

    if headers_result and headers_result.get('status') == 'ok':
        checks = headers_result.get('checks', {})
        for name, ok in checks.items():
            total_checks += 1
            if ok:
                passed += 1
            details.append({'check': name, 'passed': ok})

    if ssl_result and ssl_result.get('status') == 'ok':
        total_checks += 1
        ok = ssl_result.get('valid') is True
        if ok:
            passed += 1
        details.append({'check': 'TLS certificate validity', 'passed': ok})

    if https_result and https_result.get('status') == 'ok':
        total_checks += 1
        ok = https_result.get('https_available') is True
        if ok:
            passed += 1
        details.append({'check': 'HTTPS available', 'passed': ok})

    if cookies_result and cookies_result.get('status') == 'ok':
        chk = cookies_result.get('checks', {})
        if chk.get('has_cookies'):
            total_checks += 1
            ok = chk.get('all_secure') and chk.get('all_httponly') and chk.get('all_samesite')
            if ok:
                passed += 1
            details.append({'check': 'Cookies Secure+HttpOnly+SameSite', 'passed': ok})

    score = int((passed / total_checks) * 100) if total_checks > 0 else 0
    risk = 'Low' if score >= 80 else 'Medium' if score >= 50 else 'High'

    return score, {'total': total_checks, 'passed': passed, 'risk': risk, 'checks': details}
