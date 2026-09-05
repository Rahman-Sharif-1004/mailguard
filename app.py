"""
MailGuard - An Automated Email Safety and Phishing Detection System
Flask entry point. Run with:  python app.py
Then open http://localhost:5000 in your browser.

Everything runs locally - pasted or uploaded email content is analyzed
in-memory and is never sent to any external server (Section 37).
"""

from flask import Flask, render_template, request, flash, redirect, url_for
from mailguard_core.scorer import analyze_email

app = Flask(__name__)
app.secret_key = "mailguard-prototype-secret-key"  # only used for flash messages

MAX_INPUT_SIZE = 2 * 1024 * 1024  # 2 MB safety limit


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    raw_text = ""

    uploaded_file = request.files.get("eml_file")
    if uploaded_file and uploaded_file.filename:
        raw_bytes = uploaded_file.read(MAX_INPUT_SIZE)
        raw_text = raw_bytes.decode("utf-8", errors="ignore")
    else:
        raw_text = (request.form.get("raw_email") or "").strip()

    if not raw_text:
        flash("Please paste an email or upload a .eml file before scanning.")
        return redirect(url_for("index"))

    try:
        result = analyze_email(raw_text)
    except Exception as exc:
        flash(f"Could not analyze this message: {exc}")
        return redirect(url_for("index"))

    return render_template("result.html", result=result)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
