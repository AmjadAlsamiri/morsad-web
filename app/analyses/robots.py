from urllib.parse import urljoin, urlparse
from app.services.target_safety import safe_get


def analyze_robots(url):
    """Fetch robots.txt and return its content and whether it's present.
    """
    try:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        robots_url = urljoin(base, '/robots.txt')
        resp = safe_get(robots_url, timeout=8)
        if resp.status_code == 200:
            content = resp.text
            disallows = [line.strip() for line in content.splitlines() if line.strip().lower().startswith('disallow')]
            return {'status': 'ok', 'found': True, 'content': content, 'disallow_count': len(disallows)}
        else:
            return {'status': 'ok', 'found': False, 'http_status': resp.status_code}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}
