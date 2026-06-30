import io
import os
import pathlib
from flask import render_template


def generate_pdf(cert: dict) -> bytes:
    """Render the certificate HTML and convert to PDF bytes.

    Tries WeasyPrint first (preferred; requires GTK system libs — available on Linux/Docker).
    Falls back to xhtml2pdf (pure Python, works on Windows dev).
    """
    # Resolve logo as an absolute file:// URI so WeasyPrint/xhtml2pdf can find it
    # without needing a running HTTP server.
    logo_path = pathlib.Path(os.path.abspath(os.path.join("static", "img", "logo.png")))
    logo_src = logo_path.as_uri() if logo_path.exists() else ""

    html_content = render_template("_cert_card.html", cert=cert, pdf_mode=True, logo_src=logo_src)

    # Primary: WeasyPrint (Docker / Linux production)
    try:
        from weasyprint import HTML
        return HTML(string=html_content, base_url=os.getcwd()).write_pdf()
    except (OSError, ImportError):
        # GTK not available or WeasyPrint not installed — fall through to xhtml2pdf
        pass
    except Exception as e:
        raise RuntimeError(f"WeasyPrint failed unexpectedly: {e}") from e

    # Fallback: xhtml2pdf (pure Python, works on Windows without GTK)
    try:
        from xhtml2pdf import pisa
        buf = io.BytesIO()
        result = pisa.CreatePDF(html_content, dest=buf)
        if result.err:
            raise RuntimeError(f"xhtml2pdf error code {result.err}")
        return buf.getvalue()
    except ImportError:
        raise RuntimeError(
            "PDF generation unavailable: WeasyPrint needs GTK libraries "
            "(install via Docker/Linux) or add xhtml2pdf to requirements.txt for Windows."
        )
    except Exception as e:
        raise RuntimeError(f"xhtml2pdf failed: {e}") from e
