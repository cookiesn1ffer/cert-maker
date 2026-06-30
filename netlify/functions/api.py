"""Netlify Function: WSGI adapter for Flask (no external dependencies)."""
import base64
import io
import os
import sys

# Project root is two levels up from netlify/functions/
_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _root)
os.chdir(_root)  # Flask resolves templates/ and static/ relative to cwd

from app import app  # noqa: E402


_BINARY_TYPES = {"application/pdf", "image/png", "image/jpeg", "image/gif", "image/webp"}


def handler(event, context):
    method  = event.get("httpMethod", "GET")
    path    = event.get("path", "/")
    qs      = event.get("queryStringParameters") or {}
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    raw_body = event.get("body") or ""

    if event.get("isBase64Encoded") and raw_body:
        body = base64.b64decode(raw_body)
    else:
        body = raw_body.encode("utf-8") if isinstance(raw_body, str) else raw_body

    environ = {
        "REQUEST_METHOD":  method,
        "SCRIPT_NAME":     "",
        "PATH_INFO":       path,
        "QUERY_STRING":    "&".join(f"{k}={v}" for k, v in qs.items()),
        "SERVER_NAME":     headers.get("host", "localhost").split(":")[0],
        "SERVER_PORT":     "443",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "wsgi.version":    (1, 0),
        "wsgi.url_scheme": "https",
        "wsgi.input":      io.BytesIO(body),
        "wsgi.errors":     io.BytesIO(),
        "wsgi.multithread":  False,
        "wsgi.multiprocess": False,
        "wsgi.run_once":     True,
        "CONTENT_LENGTH":  str(len(body)),
        "CONTENT_TYPE":    headers.get("content-type", ""),
    }

    for k, v in headers.items():
        key = "HTTP_" + k.upper().replace("-", "_")
        if key not in ("HTTP_CONTENT_TYPE", "HTTP_CONTENT_LENGTH"):
            environ[key] = v

    status_holder  = [200]
    headers_holder = [{}]

    def start_response(status, response_headers, exc_info=None):
        status_holder[0]  = int(status.split(" ", 1)[0])
        headers_holder[0] = dict(response_headers)

    body_iter  = app(environ, start_response)
    body_bytes = b"".join(body_iter)

    content_type = headers_holder[0].get("Content-Type", "")
    is_binary    = any(content_type.startswith(t) for t in _BINARY_TYPES)

    return {
        "statusCode":      status_holder[0],
        "headers":         headers_holder[0],
        "isBase64Encoded": is_binary,
        "body": (
            base64.b64encode(body_bytes).decode()
            if is_binary
            else body_bytes.decode("utf-8", errors="replace")
        ),
    }
