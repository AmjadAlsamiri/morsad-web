import unittest
from unittest.mock import patch, MagicMock

class TestAnalyses(unittest.TestCase):
    @patch('app.analyses.headers.safe_get')
    def test_analyze_headers_ok(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.headers = {'Content-Security-Policy': "default-src 'self'", 'X-Frame-Options': 'DENY'}
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp

        from app.analyses.headers import analyze_headers
        res = analyze_headers('http://example.com')
        self.assertEqual(res['status'], 'ok')
        self.assertIn('content-security-policy', res['headers'])
        self.assertTrue(res['checks']['Content-Security-Policy'])

    @patch('app.analyses.ssl_check.ssl.get_server_certificate')
    def test_analyze_ssl_ok(self, mock_get_cert):
        mock_get_cert.return_value = "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkq...\n-----END CERTIFICATE-----"
        from app.analyses.ssl_check import analyze_ssl
        res = analyze_ssl('https://example.com')
        self.assertIn('status', res)

    @patch('app.analyses.dns.socket.getaddrinfo')
    def test_analyze_dns_ok(self, mock_getaddr):
        mock_getaddr.return_value = [(2,1,6,'',('93.184.216.34',0))]
        from app.analyses.dns import analyze_dns
        res = analyze_dns('https://example.com')
        self.assertEqual(res['status'], 'ok')
        self.assertIn('93.184.216.34', res['addresses'])

    @patch('app.analyses.robots.safe_get')
    def test_analyze_robots_found(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = 'User-agent: *\nDisallow: /admin'
        mock_get.return_value = mock_resp
        from app.analyses.robots import analyze_robots
        res = analyze_robots('https://example.com')
        self.assertEqual(res['status'], 'ok')
        self.assertTrue(res['found'])

    @patch('app.analyses.security_txt.safe_get')
    def test_security_txt_contact_is_detected(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = 'Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00Z'
        mock_get.return_value = mock_response
        from app.analyses.security_txt import analyze_security_txt
        result = analyze_security_txt('https://example.com')
        self.assertTrue(result['found'])
        self.assertTrue(result['has_contact'])

if __name__ == '__main__':
    unittest.main()
