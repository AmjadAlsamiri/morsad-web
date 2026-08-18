import unittest

from app.services.comparison_engine import compare_reports


class ComparisonTests(unittest.TestCase):
    def test_identifies_improvements_and_regressions(self):
        previous = {'score': 50, 'details': {'checks': [
            {'check': 'Content-Security-Policy', 'passed': False},
            {'check': 'X-Frame-Options', 'passed': True},
        ]}}
        current = {'score': 65, 'details': {'checks': [
            {'check': 'Content-Security-Policy', 'passed': True},
            {'check': 'X-Frame-Options', 'passed': False},
        ]}}
        result = compare_reports(current, previous, {
            'Content-Security-Policy': 'سياسة أمن المحتوى',
            'X-Frame-Options': 'الحماية من تضمين الإطارات',
        })
        self.assertEqual(result['score_change'], 15)
        self.assertEqual(result['improvements'], ['سياسة أمن المحتوى'])
        self.assertEqual(result['regressions'], ['الحماية من تضمين الإطارات'])


if __name__ == '__main__':
    unittest.main()
