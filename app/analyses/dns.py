import socket
from urllib.parse import urlparse
from app.services.target_safety import assert_public_host


def analyze_dns(url):
    """Resolve A and AAAA records for the host using socket.getaddrinfo.

    Returns dict with addresses and status.
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        assert_public_host(host)
        addrs = set()
        try:
            for res in socket.getaddrinfo(host, None):
                addr = res[4][0]
                addrs.add(addr)
        except Exception:
            pass
        return {'status': 'ok', 'addresses': list(addrs), 'hostname': host}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}
