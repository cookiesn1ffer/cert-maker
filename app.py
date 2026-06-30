import csv
import io
import os
from datetime import date

from dotenv import load_dotenv
from flask import (Flask, Response, flash, redirect, render_template,
                   request, session, url_for)
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from werkzeug.security import generate_password_hash

load_dotenv()

from auth import (check_rate_limit, clear_attempts, get_client_ip,
                  record_failed_attempt, require_auth_before_request,
                  verify_admin_credentials)
from models import (all_certificates_for_export, create_certificate,
                    delete_certificate, get_certificate, get_dashboard_stats,
                    init_db, list_certificates, update_admin_password,
                    update_admin_username)
from pdf_gen import generate_pdf

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
app.config["WTF_CSRF_ENABLED"] = True
app.config["WTF_CSRF_TIME_LIMIT"] = 3600
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
if os.environ.get("FLASK_ENV") != "development":
    app.config["SESSION_COOKIE_SECURE"] = True

csrf = CSRFProtect(app)


@app.before_request
def auth_gate():
    return require_auth_before_request()


@app.errorhandler(CSRFError)
def csrf_error(e):
    flash("Form expired or invalid. Please try again.", "error")
    return redirect(request.referrer or url_for("login")), 400


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("authenticated"):
        return redirect(url_for("dashboard"))

    ip = get_client_ip()
    error = None

    if request.method == "POST":
        is_locked, remaining = check_rate_limit(ip)
        if is_locked:
            error = f"Too many failed attempts. Try again in {remaining // 60}m {remaining % 60}s."
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if verify_admin_credentials(username, password):
                session.clear()
                session["authenticated"] = True
                session["username"] = username
                session.permanent = False
                clear_attempts(ip)
                return redirect(request.args.get("next") or url_for("dashboard"))
            else:
                record_failed_attempt(ip)
                is_locked, remaining = check_rate_limit(ip)
                if is_locked:
                    error = "Too many failed attempts. Locked for 15 minutes."
                else:
                    error = "Incorrect username or password."

    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ── Public: Cert Verification ─────────────────────────────────────────────────

@app.route("/verify")
def verify():
    cert_id = request.args.get("id", "").strip().upper()
    cert = None
    not_found = False
    if cert_id:
        cert = get_certificate(cert_id)
        if not cert:
            not_found = True
    return render_template("verify.html", cert_id=cert_id, cert=cert, not_found=not_found)


@app.route("/verify/<cert_id>")
def verify_cert(cert_id):
    cert = get_certificate(cert_id.upper())
    return render_template("cert_public.html", cert=cert, cert_id=cert_id.upper())


# ── Admin: Dashboard ──────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    total, recent = get_dashboard_stats()
    return render_template("dashboard.html", total=total, recent=recent)


# ── Admin: Issue ──────────────────────────────────────────────────────────────

@app.route("/issue", methods=["GET", "POST"])
def issue():
    today = date.today().isoformat()
    form_data = {
        "prefix": "CA",
        "student_name": "",
        "course_title": "",
        "cohort_label": "",
        "cohort_code": "",
        "skills": "",
        "signer_name": "",
        "signer_role": "",
        "issue_date": today,
    }

    if request.method == "POST":
        action = request.form.get("action", "preview")
        form_data = {
            "prefix": request.form.get("prefix", "CA").strip().upper(),
            "student_name": request.form.get("student_name", "").strip(),
            "course_title": request.form.get("course_title", "").strip(),
            "cohort_label": request.form.get("cohort_label", "").strip(),
            "cohort_code": request.form.get("cohort_code", "").strip(),
            "skills": request.form.get("skills", "").strip(),
            "signer_name": request.form.get("signer_name", "").strip(),
            "signer_role": request.form.get("signer_role", "").strip(),
            "issue_date": request.form.get("issue_date", today).strip(),
        }
        force_new = request.form.get("force_new") == "1"

        errors = []
        if not form_data["student_name"]:
            errors.append("Student name is required.")
        if not form_data["course_title"]:
            errors.append("Course title is required.")
        if not form_data["issue_date"]:
            errors.append("Issue date is required.")

        if action == "preview":
            preview_cert = form_data.copy()
            preview_cert["cert_id"] = f"{form_data['prefix']}-XXXX-XXXX"
            return render_template("issue.html", form_data=form_data,
                                   preview_cert=preview_cert, errors=errors)

        if errors:
            return render_template("issue.html", form_data=form_data,
                                   preview_cert=None, errors=errors)

        cert, created = create_certificate(**form_data, force_new=force_new)
        return redirect(url_for("issue_success", cert_id=cert["cert_id"],
                                created="1" if created else "0"))

    return render_template("issue.html", form_data=form_data, preview_cert=None, errors=[])


@app.route("/issue/success/<cert_id>")
def issue_success(cert_id):
    cert = get_certificate(cert_id)
    if not cert:
        flash("Certificate not found.", "error")
        return redirect(url_for("issue"))
    created = request.args.get("created", "1") == "1"
    return render_template("issue_success.html", cert=cert, created=created)


# ── Admin: Certs list ─────────────────────────────────────────────────────────

@app.route("/certs")
def certs_list():
    search = request.args.get("q", "").strip()
    sort = request.args.get("sort", "desc")
    page = max(1, int(request.args.get("page", 1)))
    per_page = 50

    certs, total = list_certificates(search=search, sort=sort, page=page, per_page=per_page)
    total_pages = max(1, (total + per_page - 1) // per_page)

    return render_template("certs_list.html", certs=certs, total=total,
                           search=search, sort=sort, page=page,
                           total_pages=total_pages, per_page=per_page)


# ── Admin: Cert detail ────────────────────────────────────────────────────────

@app.route("/certs/<cert_id>/detail")
def cert_detail(cert_id):
    cert = get_certificate(cert_id)
    if not cert:
        flash("Certificate not found.", "error")
        return redirect(url_for("certs_list"))
    return render_template("cert_detail.html", cert=cert)


@app.route("/certs/<cert_id>/delete", methods=["POST"])
def delete_cert(cert_id):
    cert = get_certificate(cert_id)
    if not cert:
        flash("Certificate not found.", "error")
    else:
        delete_certificate(cert_id)
        flash(f"Certificate {cert_id} has been deleted.", "success")
    return redirect(url_for("certs_list"))


@app.route("/certs/<cert_id>/download")
def download_cert(cert_id):
    cert = get_certificate(cert_id)
    if not cert:
        return "Certificate not found.", 404
    pdf_bytes = generate_pdf(cert)
    safe_name = cert["student_name"].replace(" ", "_")
    filename = f"{safe_name}_{cert_id}.pdf"
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )


@app.route("/certs/export.csv")
def export_csv():
    rows = all_certificates_for_export()
    fieldnames = ["id", "cert_id", "prefix", "student_name", "course_title",
                  "cohort_label", "cohort_code", "skills", "signer_name",
                  "signer_role", "issue_date", "created_at"]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=certificates.csv"},
    )


# ── Admin: Settings ───────────────────────────────────────────────────────────

@app.route("/admin/settings", methods=["GET", "POST"])
def admin_settings():
    username = session.get("username", "admin")
    error = None
    success = None

    if request.method == "POST":
        action = request.form.get("action")

        if action == "change_password":
            current = request.form.get("current_password", "")
            new_pw = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")

            if not verify_admin_credentials(username, current):
                error = "Current password is incorrect."
            elif len(new_pw) < 8:
                error = "New password must be at least 8 characters."
            elif new_pw != confirm:
                error = "New passwords do not match."
            else:
                update_admin_password(username, generate_password_hash(new_pw))
                success = "Password updated successfully."

        elif action == "change_username":
            new_uname = request.form.get("new_username", "").strip()
            confirm_pw = request.form.get("confirm_password_u", "")

            if not new_uname:
                error = "Username cannot be empty."
            elif not verify_admin_credentials(username, confirm_pw):
                error = "Password confirmation is incorrect."
            else:
                update_admin_username(username, new_uname)
                session["username"] = new_uname
                username = new_uname
                success = f"Username changed to '{new_uname}'."

    return render_template("admin_settings.html", username=username,
                           error=error, success=success)


# ── Init + run ────────────────────────────────────────────────────────────────

with app.app_context():
    init_db()

if __name__ == "__main__":
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(debug=debug, host="0.0.0.0", port=5000)
