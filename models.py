import os
import hashlib
import sqlite3
import ssl
from urllib.parse import urlparse

DB_PATH = os.environ.get("DB_PATH", "data/certs.db")


# ── Backend detection ─────────────────────────────────────────────────────────

def _pg():
    """True when a PostgreSQL DATABASE_URL is configured."""
    return bool(os.environ.get("DATABASE_URL"))


def _q(sql):
    """Convert ? placeholders to %s for PostgreSQL."""
    return sql.replace("?", "%s") if _pg() else sql


def _parse_pg_url():
    """Parse a postgresql:// URL into pg8000 keyword arguments."""
    url = urlparse(os.environ["DATABASE_URL"])
    if url.scheme not in ("postgres", "postgresql"):
        raise ValueError("DATABASE_URL must use postgresql:// scheme")
    return {
        "user": url.username,
        "password": url.password,
        "host": url.hostname,
        "port": url.port or 5432,
        "database": url.path.lstrip("/") if url.path else "",
        "ssl_context": ssl.create_default_context(),
    }


# ── Connection context manager ────────────────────────────────────────────────

class _DB:
    """Context manager that opens a DB connection and commits/rollbacks on exit."""

    def __enter__(self):
        if _pg():
            import pg8000.dbapi
            self._conn = pg8000.dbapi.connect(**_parse_pg_url())
        else:
            os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
            self._conn = sqlite3.connect(DB_PATH)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
        return self

    def __exit__(self, exc, *_):
        if exc:
            self._conn.rollback()
        else:
            self._conn.commit()
        self._conn.close()

    @staticmethod
    def _row_to_dict(cursor, row):
        if row is None or cursor.description is None:
            return None
        columns = [desc[0] for desc in cursor.description]
        return dict(zip(columns, row))

    def run(self, sql, params=()):
        cur = self._conn.cursor()
        cur.execute(_q(sql), params)
        return cur

    def one(self, sql, params=()):
        cur = self.run(sql, params)
        row = cur.fetchone()
        return self._row_to_dict(cur, row)

    def all(self, sql, params=()):
        cur = self.run(sql, params)
        rows = cur.fetchall()
        if not rows:
            return []
        columns = [desc[0] for desc in cur.description]
        return [dict(zip(columns, row)) for row in rows]


# ── Schema ────────────────────────────────────────────────────────────────────

_CERTS_DDL_PG = """
    CREATE TABLE IF NOT EXISTS certificates (
        id           SERIAL PRIMARY KEY,
        cert_id      TEXT    NOT NULL UNIQUE,
        prefix       TEXT    NOT NULL DEFAULT 'CA',
        student_name TEXT    NOT NULL,
        course_title TEXT    NOT NULL,
        cohort_label TEXT    NOT NULL DEFAULT '',
        cohort_code  TEXT    NOT NULL DEFAULT '',
        skills       TEXT    NOT NULL DEFAULT '',
        signer_name  TEXT    NOT NULL DEFAULT '',
        signer_role  TEXT    NOT NULL DEFAULT '',
        issue_date   DATE    NOT NULL,
        created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
"""

_CERTS_DDL_SQLITE = """
    CREATE TABLE IF NOT EXISTS certificates (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        cert_id      TEXT    NOT NULL UNIQUE,
        prefix       TEXT    NOT NULL DEFAULT 'CA',
        student_name TEXT    NOT NULL,
        course_title TEXT    NOT NULL,
        cohort_label TEXT    NOT NULL DEFAULT '',
        cohort_code  TEXT    NOT NULL DEFAULT '',
        skills       TEXT    NOT NULL DEFAULT '',
        signer_name  TEXT    NOT NULL DEFAULT '',
        signer_role  TEXT    NOT NULL DEFAULT '',
        issue_date   DATE    NOT NULL,
        created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
"""

_ADMIN_DDL_PG = """
    CREATE TABLE IF NOT EXISTS admin_users (
        id            SERIAL PRIMARY KEY,
        username      TEXT    NOT NULL UNIQUE,
        password_hash TEXT    NOT NULL,
        created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
"""

_ADMIN_DDL_SQLITE = """
    CREATE TABLE IF NOT EXISTS admin_users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        username      TEXT    NOT NULL UNIQUE,
        password_hash TEXT    NOT NULL,
        created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
"""


def init_db():
    with _DB() as db:
        if _pg():
            db.run(_CERTS_DDL_PG)
            db.run(_ADMIN_DDL_PG)
        else:
            db.run(_CERTS_DDL_SQLITE)
            db.run(_ADMIN_DDL_SQLITE)
    _migrate_env_admin()


def _migrate_env_admin():
    """Seed an 'admin' account from legacy ADMIN_PASSWORD_HASH env var (one-time)."""
    env_hash = os.environ.get("ADMIN_PASSWORD_HASH", "")
    if not env_hash:
        return
    with _DB() as db:
        count = db.one("SELECT COUNT(*) AS c FROM admin_users")["c"]
        if count == 0:
            username = os.environ.get("ADMIN_USERNAME", "admin")
            if _pg():
                db.run(
                    "INSERT INTO admin_users (username, password_hash) VALUES (?, ?) ON CONFLICT DO NOTHING",
                    (username, env_hash),
                )
            else:
                db.run(
                    "INSERT OR IGNORE INTO admin_users (username, password_hash) VALUES (?, ?)",
                    (username, env_hash),
                )


# ── Admin CRUD ────────────────────────────────────────────────────────────────

def get_admin_by_username(username: str):
    with _DB() as db:
        return db.one("SELECT * FROM admin_users WHERE username=?", (username,))


def get_admin_count() -> int:
    with _DB() as db:
        return db.one("SELECT COUNT(*) AS c FROM admin_users")["c"]


def create_admin_user(username: str, password_hash: str):
    with _DB() as db:
        db.run(
            "INSERT INTO admin_users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )


def update_admin_password(username: str, new_hash: str):
    with _DB() as db:
        db.run(
            "UPDATE admin_users SET password_hash=? WHERE username=?",
            (new_hash, username),
        )


def update_admin_username(old_username: str, new_username: str):
    with _DB() as db:
        db.run(
            "UPDATE admin_users SET username=? WHERE username=?",
            (new_username, old_username),
        )


# ── Certificate CRUD ──────────────────────────────────────────────────────────

def _generate_cert_id(prefix, student_name, course_title, issue_date, salt=""):
    raw = f"{student_name}|{course_title}|{issue_date}{salt}"
    digest = hashlib.sha256(raw.encode()).hexdigest().upper()
    return f"{prefix}-{digest[:4]}-{digest[4:8]}"


def find_existing_cert(student_name, course_title, issue_date):
    with _DB() as db:
        return db.one(
            "SELECT * FROM certificates WHERE student_name=? AND course_title=? AND issue_date=?",
            (student_name, course_title, issue_date),
        )


def create_certificate(prefix, student_name, course_title, cohort_label, cohort_code,
                       skills, signer_name, signer_role, issue_date, force_new=False):
    if not force_new:
        existing = find_existing_cert(student_name, course_title, str(issue_date))
        if existing:
            return existing, False

    salt_counter = ""
    attempt = 0
    while True:
        cert_id = _generate_cert_id(prefix, student_name, course_title, str(issue_date), salt_counter)
        with _DB() as db:
            collision = db.one(
                "SELECT student_name, course_title, issue_date FROM certificates WHERE cert_id=?",
                (cert_id,),
            )
        if collision is None:
            break
        if (collision["student_name"] == student_name and
                collision["course_title"] == course_title and
                str(collision["issue_date"]) == str(issue_date)):
            with _DB() as db:
                return db.one("SELECT * FROM certificates WHERE cert_id=?", (cert_id,)), False
        attempt += 1
        salt_counter = f"-{attempt}"

    row_data = {
        "cert_id": cert_id,
        "prefix": prefix,
        "student_name": student_name,
        "course_title": course_title,
        "cohort_label": cohort_label,
        "cohort_code": cohort_code,
        "skills": skills,
        "signer_name": signer_name,
        "signer_role": signer_role,
        "issue_date": str(issue_date),
    }
    with _DB() as db:
        db.run("""
            INSERT INTO certificates
                (cert_id, prefix, student_name, course_title, cohort_label, cohort_code,
                 skills, signer_name, signer_role, issue_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (cert_id, prefix, student_name, course_title, cohort_label, cohort_code,
              skills, signer_name, signer_role, str(issue_date)))
    return row_data, True


def get_certificate(cert_id: str):
    with _DB() as db:
        return db.one("SELECT * FROM certificates WHERE cert_id=?", (cert_id,))


def delete_certificate(cert_id: str):
    with _DB() as db:
        db.run("DELETE FROM certificates WHERE cert_id=?", (cert_id,))


def list_certificates(search="", sort="desc", page=1, per_page=50):
    offset = (page - 1) * per_page
    order = "DESC" if sort == "desc" else "ASC"
    with _DB() as db:
        if search:
            like = f"%{search}%"
            rows = db.all(f"""
                SELECT * FROM certificates
                WHERE student_name LIKE ? OR course_title LIKE ? OR cert_id LIKE ?
                ORDER BY issue_date {order}, id {order}
                LIMIT ? OFFSET ?
            """, (like, like, like, per_page, offset))
            total = db.one("""
                SELECT COUNT(*) AS c FROM certificates
                WHERE student_name LIKE ? OR course_title LIKE ? OR cert_id LIKE ?
            """, (like, like, like))["c"]
        else:
            rows = db.all(f"""
                SELECT * FROM certificates
                ORDER BY issue_date {order}, id {order}
                LIMIT ? OFFSET ?
            """, (per_page, offset))
            total = db.one("SELECT COUNT(*) AS c FROM certificates")["c"]
    return rows, total


def get_dashboard_stats():
    with _DB() as db:
        total = db.one("SELECT COUNT(*) AS c FROM certificates")["c"]
        recent = db.all("SELECT * FROM certificates ORDER BY created_at DESC LIMIT 5")
    return total, recent


def all_certificates_for_export():
    with _DB() as db:
        return db.all("SELECT * FROM certificates ORDER BY issue_date DESC")
