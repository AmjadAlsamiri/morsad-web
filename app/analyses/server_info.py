def analyze_server_info(headers_result):
    """Extract Server and X-Powered-By headers and flag version leakage.

    headers_result: output dict from analyze_headers
    """
    try:
        if headers_result.get('status') != 'ok':
            return {'status': 'error', 'error': 'headers not available'}
        hdrs = headers_result.get('headers', {})
        server = hdrs.get('server')
        xpb = hdrs.get('x-powered-by') or hdrs.get('x-generator')
        leakage = False
        if server and any(ch.isdigit() for ch in server):
            leakage = True
        return {'status': 'ok', 'server_header': server, 'x_powered_by': xpb, 'version_leakage': leakage}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}
