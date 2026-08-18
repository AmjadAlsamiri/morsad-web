def assess_risk(score, details, findings):
    """Assess risk level based on score and presence of critical findings.

    Returns dict with risk_level (Low/Medium/High/Critical) and reasons.
    """
    reasons = []
    risk = 'Low'
    if score >= 85:
        risk = 'Low'
    elif score >= 60:
        risk = 'Medium'
    else:
        risk = 'High'

    ssl = findings.get('ssl', {})
    https = findings.get('https', {})
    admin = findings.get('admin_pages', {})
    hdrs = findings.get('headers', {})

    if ssl.get('status') == 'ok' and not ssl.get('valid'):
        reasons.append('شهادة TLS منتهية أو غير صالحة')
        risk = 'Critical'
    if https.get('status') == 'ok' and not https.get('https_available'):
        reasons.append('لا يوجد دعم HTTPS')
        risk = 'Critical'
    if admin.get('status') == 'ok' and admin.get('found'):
        reasons.append('صفحات الإدارة مكشوفة')
        if risk != 'Critical':
            risk = 'High'
    if hdrs.get('status') == 'ok':
        checks = hdrs.get('checks', {})
        if not checks.get('Content-Security-Policy'):
            reasons.append('غياب Content-Security-Policy قد يسهل هجمات XSS')
            if risk == 'Low':
                risk = 'Medium'
        profile = hdrs.get('profile', {})
        if profile.get('cors_wildcard'):
            reasons.append('سياسة CORS تسمح بكل المصادر عبر الرمز *')
            if risk == 'Low':
                risk = 'Medium'
        if profile.get('csp_uses_unsafe_directives'):
            reasons.append('سياسة CSP تتضمن توجيهات غير آمنة')
            if risk == 'Low':
                risk = 'Medium'

    return {'risk': risk, 'reasons': reasons}
