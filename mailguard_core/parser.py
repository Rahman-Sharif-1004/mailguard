"""
Parsing Layer (Section 13/14 of the report).
Takes raw email text (pasted, or from an uploaded .eml file) and splits it
into headers, body text, embedded URLs, and attachment metadata.
Nothing here ever makes a network call - everything is local, in-memory.
"""

import re
from email import message_from_string, policy
from email.parser import Parser

URL_RE = re.compile(r'https?://[^\s\'"<>\)]+', re.IGNORECASE)

HIGH_RISK_EXTENSIONS = {'.exe', '.scr', '.bat', '.js', '.vbs', '.docm', '.xlsm', '.jar', '.msi'}


def parse_email(raw_text: str) -> dict:
    """
    Returns a dict:
      headers: dict of header-name -> value
      body: plain-text body (HTML tags stripped if needed)
      urls: list of URLs found in the body
      attachments: list of {filename, content_type}
    """
    msg = Parser(policy=policy.default).parsestr(raw_text)

    headers = {k: v for k, v in msg.items()}

    body_text = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition") or "")
            filename = part.get_filename()

            if filename:
                attachments.append({
                    "filename": filename,
                    "content_type": part.get_content_type(),
                })
                continue

            if part.get_content_type() == "text/plain" and "attachment" not in content_disposition:
                try:
                    body_text += part.get_content()
                except Exception:
                    pass
            elif part.get_content_type() == "text/html" and "attachment" not in content_disposition and not body_text:
                try:
                    body_text += _strip_html(part.get_content())
                except Exception:
                    pass
    else:
        try:
            content = msg.get_content()
        except Exception:
            content = raw_text
        if msg.get_content_type() == "text/html":
            body_text = _strip_html(content)
        else:
            body_text = content

    urls = URL_RE.findall(body_text)

    return {
        "headers": headers,
        "body": body_text.strip(),
        "urls": urls,
        "attachments": attachments,
    }


def _strip_html(html: str) -> str:
    """Very small HTML-tag stripper (keeps link text readable)."""
    text = re.sub(r'<(script|style)[^>]*>.*?</\1>', ' ', html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<[^>]+>', ' ', text)
    return re.sub(r'\s+', ' ', text).strip()
