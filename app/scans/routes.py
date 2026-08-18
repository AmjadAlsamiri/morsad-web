import json
import io
from datetime import datetime, timezone

from flask import Blueprint, render_template, request, send_file, jsonify
from app.analyses.headers import analyze_headers
from app.analyses.ssl_check import analyze_ssl
from app.analyses.dns import analyze_dns
from app.analyses.https_check import analyze_https
from app.analyses.cookies import analyze_cookies
from app.analyses.robots import analyze_robots
from app.analyses.sitemap import analyze_sitemap
from app.analyses.admin_pages import analyze_admin_pages
from app.analyses.server_info import analyze_server_info
from app.analyses.security_txt import analyze_security_txt
from app.services.score_engine import compute_score
from app.services.recommendation_engine import generate_recommendations
from app.services.risk_engine import assess_risk
from app.reports.generator import render_pdf_report
from app.db import get_db
from app.services.target_safety import TargetError, normalize_target
from app.services.comparison_engine import compare_reports

scans_bp = Blueprint('scans', __name__)

RISK_LABELS = {'Low': 'منخفضة', 'Medium': 'متوسطة', 'High': 'مرتفعة', 'Critical': 'حرجة'}
CHECK_LABELS = {
    'Strict-Transport-Security': 'تفعيل HSTS',
    'Content-Security-Policy': 'سياسة أمن المحتوى',
    'X-Frame-Options': 'الحماية من تضمين الإطارات',
    'X-Content-Type-Options': 'منع تخمين نوع المحتوى',
    'Referrer-Policy': 'سياسة المُحيل',
    'Permissions-Policy': 'سياسة الصلاحيات',
    'TLS certificate validity': 'صلاحية شهادة TLS',
    'HTTPS available': 'توفر اتصال HTTPS',
    'Cookies Secure+HttpOnly': 'حماية ملفات تعريف الارتباط',
    'Cookies Secure+HttpOnly+SameSite': 'حماية ملفات تعريف الارتباط',
    'CSP avoids unsafe directives': 'تجنب توجيهات CSP غير الآمنة',
    'CORS wildcard not present': 'تقييد المصادر المسموح لها عبر CORS',
    'Cross-origin isolation policy': 'سياسة عزل الموارد بين المصادر',
}


@scans_bp.route('/', methods=['GET'])
def index():
    rows = get_db().execute(
        'SELECT id, target, created_at, score, risk FROM scans ORDER BY id DESC LIMIT 8'
    ).fetchall()
    history = [dict(row) for row in rows]
    for item in history:
        item['risk_label'] = RISK_LABELS.get(item['risk'], item['risk'])
    summary = get_db().execute(
        'SELECT COUNT(*) AS total, ROUND(AVG(score)) AS average FROM scans'
    ).fetchone()
    return render_template('index.html', history=history, summary=dict(summary))


@scans_bp.route('/scan', methods=['POST'])
def scan():
    if request.form.get('authorized') != 'yes':
        return render_template('index.html', error='يجب تأكيد ملكية الموقع أو وجود تصريح صريح للفحص.',
                               history=[], summary={'total': 0, 'average': 0}), 400
    try:
        url = normalize_target(request.form.get('url'))
    except TargetError as exc:
        return render_template('index.html', error=str(exc), history=[], summary={'total': 0, 'average': 0}), 400

    headers_result = analyze_headers(url)
    ssl_result = analyze_ssl(url)
    dns_result = analyze_dns(url)
    https_result = analyze_https(url)
    cookies_result = analyze_cookies(url)
    robots_result = analyze_robots(url)
    sitemap_result = analyze_sitemap(url)
    admin_result = analyze_admin_pages(url)
    server_info_result = analyze_server_info(headers_result)
    security_txt_result = analyze_security_txt(url)

    score, details = compute_score(headers_result, ssl_result, https_result, cookies_result)

    findings = {
        'headers': headers_result,
        'ssl': ssl_result,
        'dns': dns_result,
        'https': https_result,
        'cookies': cookies_result,
        'robots': robots_result,
        'sitemap': sitemap_result,
        'admin_pages': admin_result,
        'server_info': server_info_result,
        'security_txt': security_txt_result,
        'score': score,
        'details': details,
        'target': url
    }

    risk = assess_risk(score, details, findings)
    risk['label'] = RISK_LABELS.get(risk['risk'], risk['risk'])
    recommendations = generate_recommendations(findings)
    findings['risk_assessment'] = risk
    findings['recommendations'] = recommendations
    findings['metadata'] = {
        'generated_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
        'scope': 'فحص دفاعي محدود لموقع مصرح به',
    }
    db = get_db()
    result = db.execute(
        'INSERT INTO scans (target, score, risk, findings_json) VALUES (?, ?, ?, ?)',
        (url, score, risk['risk'], json.dumps(findings, ensure_ascii=False)),
    )
    db.commit()

    previous = db.execute(
        'SELECT id FROM scans WHERE target = ? AND id < ? ORDER BY id DESC LIMIT 1',
        (url, result.lastrowid),
    ).fetchone()
    return render_template('result.html', findings=findings, scan_id=result.lastrowid,
                           check_labels=CHECK_LABELS, comparison_available=previous is not None)


@scans_bp.route('/scan/<int:scan_id>', methods=['GET'])
def saved_scan(scan_id):
    """Open a stored local report without running a new scan."""
    row = get_db().execute('SELECT findings_json FROM scans WHERE id = ?', (scan_id,)).fetchone()
    if row is None:
        return render_template('index.html', error='التقرير المطلوب غير موجود.', history=[],
                               summary={'total': 0, 'average': 0}), 404
    findings = json.loads(row['findings_json'])
    previous = get_db().execute(
        'SELECT id FROM scans WHERE target = ? AND id < ? ORDER BY id DESC LIMIT 1',
        (findings['target'], scan_id),
    ).fetchone()
    return render_template('result.html', findings=findings, scan_id=scan_id,
                           check_labels=CHECK_LABELS, comparison_available=previous is not None)


@scans_bp.route('/scan/<int:scan_id>/comparison', methods=['GET'])
def comparison(scan_id):
    db = get_db()
    row = db.execute('SELECT target, findings_json FROM scans WHERE id = ?', (scan_id,)).fetchone()
    if row is None:
        return render_template('index.html', error='التقرير المطلوب غير موجود.', history=[], summary={}), 404
    previous = db.execute(
        'SELECT id, findings_json FROM scans WHERE target = ? AND id < ? ORDER BY id DESC LIMIT 1',
        (row['target'], scan_id),
    ).fetchone()
    if previous is None:
        return render_template('index.html', error='لا يوجد فحص سابق للموقع لمقارنته.', history=[], summary={}), 404
    current_findings = json.loads(row['findings_json'])
    previous_findings = json.loads(previous['findings_json'])
    result = compare_reports(current_findings, previous_findings, CHECK_LABELS)
    return render_template('comparison.html', target=row['target'], scan_id=scan_id,
                           previous_id=previous['id'], comparison=result)


@scans_bp.route('/report', methods=['POST'])
def report():
    data = request.get_json()
    scan_id = data.get('scan_id') if data else None
    if not isinstance(scan_id, int):
        return jsonify(error='رقم التقرير مطلوب.'), 400
    row = get_db().execute('SELECT findings_json FROM scans WHERE id = ?', (scan_id,)).fetchone()
    if row is None:
        return jsonify(error='التقرير غير موجود.'), 404
    findings = json.loads(row['findings_json'])
    html = render_template('report.html', findings=findings, check_labels=CHECK_LABELS)
    pdf_bytes = render_pdf_report(html)
    if pdf_bytes:
        return send_file(io.BytesIO(pdf_bytes), mimetype='application/pdf', as_attachment=True, download_name='mirsad_report.pdf')
    return html, 200, {'Content-Type': 'text/html; charset=utf-8'}
