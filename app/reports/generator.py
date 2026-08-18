import io


def render_pdf_report(html):
    """Attempt to render PDF from HTML. Try WeasyPrint first, then xhtml2pdf as fallback.

    Returns bytes of PDF or None if not possible.
    """
    try:
        from weasyprint import HTML
        pdf = HTML(string=html).write_pdf()
        return pdf
    except Exception:
        pass

    try:
        from xhtml2pdf import pisa
        out = io.BytesIO()
        pisa_status = pisa.CreatePDF(html, dest=out)
        if not pisa_status.err:
            return out.getvalue()
    except Exception:
        pass

    return None
