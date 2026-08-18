def generate_recommendations(findings):
    """Generate human-readable recommendations based on findings dict.

    findings: dict with keys headers, ssl, dns, https, cookies, robots, sitemap, admin_pages, server_info
    """
    recs = []
    hdrs = findings.get('headers', {})
    if hdrs.get('status') == 'ok':
        checks = hdrs.get('checks', {})
        if not checks.get('Strict-Transport-Security'):
            recs.append('تفعيل HSTS عبر إضافة هيدر Strict-Transport-Security لتقوية الاتصال عبر HTTPS')
        if not checks.get('Content-Security-Policy'):
            recs.append('إضافة Content-Security-Policy لتقليل مخاطر XSS ومحتوى غير موثوق')
        if not checks.get('X-Frame-Options'):
            recs.append('إضافة X-Frame-Options لمنع clickjacking')
        if not checks.get('X-Content-Type-Options'):
            recs.append('إضافة X-Content-Type-Options: nosniff')
        if checks.get('Content-Security-Policy') and not checks.get('CSP avoids unsafe directives'):
            recs.append('مراجعة سياسة CSP وإزالة unsafe-inline وunsafe-eval كلما أمكن')
        if not checks.get('CORS wildcard not present'):
            recs.append('تقييد Access-Control-Allow-Origin بالنطاقات الموثوقة بدل استخدام الرمز *')
    ssl = findings.get('ssl', {})
    if ssl.get('status') == 'ok' and not ssl.get('valid'):
        recs.append('تجديد شهادة TLS/SSL لأنها منتهية أو غير صالحة')
    if ssl.get('status') != 'ok':
        recs.append('فشل الحصول على معلومات الشهادة — تحقق من وصول المنصة إلى الهدف')
    https = findings.get('https', {})
    if https.get('status') == 'ok' and not https.get('https_available'):
        recs.append('تفعيل HTTPS على الخادم — لا يوجد استجابة عبر HTTPS')
    if https.get('status') == 'ok' and not https.get('redirects_to_https'):
        recs.append('إعادة توجيه تلقائي من HTTP إلى HTTPS لتأمين الاتصالات')
    cookies = findings.get('cookies', {})
    if cookies.get('status') == 'ok':
        checks = cookies.get('checks', {})
        if checks.get('has_cookies') and not checks.get('all_secure'):
            recs.append('وضع علم Secure لكافة الكوكيز الحساسة')
        if checks.get('has_cookies') and not checks.get('all_httponly'):
            recs.append('وضع علم HttpOnly للكوكيز للحد من وصول الجافاسكربت إليها')
        if checks.get('has_cookies') and not checks.get('all_samesite'):
            recs.append('تحديد خاصية SameSite لملفات الارتباط لتقليل مخاطر الطلبات العابرة للمواقع')
    robots = findings.get('robots', {})
    if robots.get('status') == 'ok' and not robots.get('found'):
        recs.append('إضافة robots.txt إن لم تكن موجودة لتنظيم سياسة الزحف')
    sitemap = findings.get('sitemap', {})
    if sitemap.get('status') == 'ok' and not sitemap.get('found'):
        recs.append('إنشاء sitemap.xml لتحسين اكتشاف صفحات الموقع بواسطة محركات البحث')
    admin = findings.get('admin_pages', {})
    if admin.get('status') == 'ok' and admin.get('found'):
        recs.append('صفحات الإدارة مكشوفة عبر مسارات شائعة — النظر في نقلها أو حمايتها بمصادقة/تقييد عنوان IP')
    server = findings.get('server_info', {})
    if server.get('status') == 'ok' and server.get('version_leakage'):
        recs.append('تجنب تسريب إصدارات الخادم في هيدر Server وX-Powered-By')

    if not recs:
        recs.append('لا توجد توصيات حرجة — تأكد من متابعة أفضل الممارسات والتحقق الدوري')

    return recs
