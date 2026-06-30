from collections import defaultdict
from datetime import datetime, timedelta
from functools import wraps

from flask import redirect, request, session, url_for
from werkzeug.security import check_password_hash

_login_attempts = defaultdict(lambda: {"count": 0, "locked_until": None, "attempts": []})

LOCKOUT_ATTEMPTS = 5
LOCKOUT_WINDOW = timedelta(minutes=15)
LOCKOUT_DURATION = timedelta(minutes=15)

# Endpoints that don't require authentication
OPEN_ENDPOINTS = {"login", "static", "verify", "verify_cert", "download_cert"}


def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For")
    addr = forwarded if forwarded else (request.remote_addr or "127.0.0.1")
    return addr.split(",")[0].strip()


def check_rate_limit(ip: str) -> tuple[bool, int]:
    state = _login_attempts[ip]
    now = datetime.utcnow()

    if state["locked_until"] and now < state["locked_until"]:
        remaining = int((state["locked_until"] - now).total_seconds())
        return True, remaining

    if state["locked_until"] and now >= state["locked_until"]:
        state["count"] = 0
        state["locked_until"] = None
        state["attempts"] = []

    state["attempts"] = [t for t in state["attempts"] if now - t < LOCKOUT_WINDOW]
    return False, 0


def record_failed_attempt(ip: str):
    state = _login_attempts[ip]
    now = datetime.utcnow()
    state["attempts"].append(now)
    state["attempts"] = [t for t in state["attempts"] if now - t < LOCKOUT_WINDOW]
    state["count"] = len(state["attempts"])
    if state["count"] >= LOCKOUT_ATTEMPTS:
        state["locked_until"] = now + LOCKOUT_DURATION


def clear_attempts(ip: str):
    _login_attempts[ip] = {"count": 0, "locked_until": None, "attempts": []}


def verify_admin_credentials(username: str, password: str) -> bool:
    from models import get_admin_by_username
    admin = get_admin_by_username(username)
    if admin:
        return check_password_hash(admin["password_hash"], password)
    return False


def require_auth_before_request():
    if request.endpoint in OPEN_ENDPOINTS or request.endpoint is None:
        return
    if not session.get("authenticated"):
        return redirect(url_for("login", next=request.path))
