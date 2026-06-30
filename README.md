# Cookie's Academy — Certificate Manager

A self-hosted Flask app for issuing and tracking course-completion certificates. Single-admin, private tool — no public-facing functionality.

## Local dev setup

```bash
# 1. Create and activate venv
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Copy env template and fill in values
cp .env.example .env

# 4. Generate a password hash
python scripts/set_password.py "your-password-here"
# Paste the printed ADMIN_PASSWORD_HASH= line into .env

# 5. Also set SECRET_KEY in .env to a long random string, e.g.:
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"

# 6. Run (dev mode)
FLASK_ENV=development python app.py
# or: flask --app app run --debug
```

App runs at http://localhost:5000. Log in with the password you set.

## Docker

```bash
# Copy and edit .env first (see above)
cp .env.example .env
# edit .env — set SECRET_KEY and ADMIN_PASSWORD_HASH

docker compose up --build -d
# App at http://localhost:5000
```

The SQLite database is persisted in `./data/certs.db` via a bind mount.

## Security note

This tool has **no public-facing intent**. The login page is the only access control. Deploy it on a private network (Tailscale is ideal) or behind a reverse proxy (Caddy/nginx) with HTTPS. **Do not expose port 5000 on a public IP without at minimum the login gate and HTTPS active.**

Recommended setups:
- Tailscale + `tailscale serve` for HTTPS on your tailnet
- Caddy reverse proxy with `reverse_proxy localhost:5000`
- nginx + Certbot

## Resetting a locked-out password

Regenerate the hash and restart:

```bash
python scripts/set_password.py "new-password"
# paste into .env
# restart the app (or `docker compose restart`)
```

## Project structure

```
app.py           — Flask app, all routes
auth.py          — Login logic, brute-force protection, before_request gate
models.py        — SQLite helpers, cert_id generation
pdf_gen.py       — WeasyPrint PDF renderer
templates/       — Jinja2 HTML
static/style.css — All styles (shared browser + cert card)
scripts/         — CLI helpers
data/certs.db    — SQLite database (gitignored)
```
