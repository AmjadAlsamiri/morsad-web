from urllib.parse import urljoin, urlparse
from app.services.target_safety import safe_get


def analyze_sitemap(url):
    """Try to fetch sitemap.xml and report whether it exists and basic info.
    """
    try:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        sitemap_url = urljoin(base, '/sitemap.xml')
        resp = safe_get(sitemap_url, timeout=8)
        if resp.status_code == 200 and ('xml' in resp.headers.get('content-type','')):
            size = len(resp.content)
            return {'status': 'ok', 'found': True, 'size_bytes': size, 'content_snippet': resp.text[:200]}
        else:
            return {'status': 'ok', 'found': False, 'http_status': resp.status_code}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}
