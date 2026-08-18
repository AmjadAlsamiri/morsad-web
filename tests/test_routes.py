import os
import tempfile
import unittest
from unittest.mock import patch

from app import create_app


class RoutesTests(unittest.TestCase):
    def setUp(self):
        handle = tempfile.NamedTemporaryFile(delete=False)
        handle.close()
        self.path = handle.name
        self.app = create_app()
        self.app.config.update(TESTING=True, DATABASE=self.path)
        from app.db import init_db
        with self.app.app_context():
            init_db()
        self.client = self.app.test_client()

    def tearDown(self):
        os.unlink(self.path)

    def test_requires_authorization(self):
        response = self.client.post('/scan', data={'url': 'example.com'})
        self.assertEqual(response.status_code, 400)

    @patch('app.scans.routes.normalize_target', return_value='https://example.com')
    @patch('app.scans.routes.analyze_security_txt', return_value={'status': 'ok', 'found': False})
    @patch('app.scans.routes.analyze_server_info', return_value={'status': 'ok', 'version_leakage': False})
    @patch('app.scans.routes.analyze_admin_pages', return_value={'status': 'ok', 'found': []})
    @patch('app.scans.routes.analyze_sitemap', return_value={'status': 'ok', 'found': False})
    @patch('app.scans.routes.analyze_robots', return_value={'status': 'ok', 'found': False})
    @patch('app.scans.routes.analyze_cookies', return_value={'status': 'ok', 'checks': {'has_cookies': False}})
    @patch('app.scans.routes.analyze_https', return_value={'status': 'ok', 'https_available': True, 'redirects_to_https': True})
    @patch('app.scans.routes.analyze_dns', return_value={'status': 'ok', 'addresses': []})
    @patch('app.scans.routes.analyze_ssl', return_value={'status': 'ok', 'valid': True})
    @patch('app.scans.routes.analyze_headers', return_value={'status': 'ok', 'checks': {}})
    def test_authorized_scan_is_saved(self, *_mocks):
        response = self.client.post('/scan', data={'url': 'example.com', 'authorized': 'yes'})
        self.assertEqual(response.status_code, 200)
        with self.app.app_context():
            from app.db import get_db
            self.assertEqual(get_db().execute('SELECT COUNT(*) FROM scans').fetchone()[0], 1)
            scan_id = get_db().execute('SELECT id FROM scans').fetchone()[0]
        detail = self.client.get(f'/scan/{scan_id}')
        self.assertEqual(detail.status_code, 200)
        self.assertIn('تقرير أمان الموقع'.encode(), detail.data)
        with patch('app.scans.routes.render_pdf_report', return_value=b'%PDF-test'):
            pdf = self.client.post('/report', json={'scan_id': scan_id})
        self.assertEqual(pdf.status_code, 200)
        self.assertEqual(pdf.mimetype, 'application/pdf')

    def test_missing_saved_report_returns_404(self):
        self.assertEqual(self.client.get('/scan/99999').status_code, 404)


if __name__ == '__main__':
    unittest.main()
