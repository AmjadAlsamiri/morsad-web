import unittest
from unittest.mock import MagicMock, patch

from app.services.target_safety import TargetError, normalize_target, safe_get


class TargetSafetyTests(unittest.TestCase):
    def test_private_ip_is_rejected(self):
        with self.assertRaises(TargetError):
            normalize_target('http://127.0.0.1')

    @patch('app.services.target_safety.assert_public_host')
    @patch('app.services.target_safety.requests.get')
    def test_redirect_destinations_are_checked(self, mock_get, mock_public):
        redirect = MagicMock(status_code=302, headers={'location': 'https://next.example'})
        final = MagicMock(status_code=200, headers={})
        mock_get.side_effect = [redirect, final]
        response = safe_get('https://example.com')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(mock_public.call_count, 2)


if __name__ == '__main__':
    unittest.main()
