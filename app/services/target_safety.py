"""Safety controls for explicitly authorized, public web targets only."""
import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import requests


class TargetError(ValueError):
    pass


def normalize_target(value):
    value = (value or "").strip()
    if not value:
        raise TargetError("أدخل رابط الموقع أو نطاقه.")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TargetError("أدخل رابط HTTP أو HTTPS صالحًا.")
    if parsed.username or parsed.password:
        raise TargetError("لا يسمح الرابط ببيانات تسجيل الدخول.")
    if parsed.port and parsed.port not in {80, 443}:
        raise TargetError("يسمح بالفحص عبر المنفذين 80 و443 فقط.")
    assert_public_host(parsed.hostname)
    return parsed.geturl()


def assert_public_host(hostname):
    hostname = hostname.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith(".local"):
        raise TargetError("لا يمكن فحص عناوين محلية أو داخلية.")
    try:
        addresses = {entry[4][0] for entry in socket.getaddrinfo(hostname, None)}
    except socket.gaierror as exc:
        raise TargetError("تعذر العثور على عنوان النطاق.") from exc
    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise TargetError("لا يمكن فحص عنوان خاص أو محجوز.")


def _safe_request(method, url, timeout, max_redirects=4):
    """Make a read-only request and validate every redirect destination."""
    for _ in range(max_redirects + 1):
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise TargetError("تضمنت إعادة التوجيه رابطًا غير صالح.")
        assert_public_host(parsed.hostname)
        request_func = requests.get if method == "GET" else requests.head
        response = request_func(url, timeout=timeout, allow_redirects=False,
                                headers={"User-Agent": "Mirsad-Web/2.0 (authorized defensive check)"})
        location = response.headers.get("location")
        if response.status_code in {301, 302, 303, 307, 308} and location:
            url = urljoin(url, location)
            continue
        return response
    raise TargetError("تجاوز الموقع الحد الآمن لإعادات التوجيه.")


def safe_get(url, timeout=10):
    return _safe_request("GET", url, timeout)


def safe_head(url, timeout=10):
    return _safe_request("HEAD", url, timeout)
