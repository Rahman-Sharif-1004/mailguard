"""
Content Analysis / NLP (Section 19 of the report) - weight 25%.
Uses the trained TF-IDF + MultinomialNB classifier (Section 21) plus a
few hand-crafted linguistic features (Section 16) - urgency keywords and
generic greetings.
"""

import os
import re
import joblib

WEIGHT = 25
_MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "model", "classifier.joblib")
_model = None

URGENCY_WORDS = [
    "urgent", "immediately", "verify your account", "act now", "suspended",
    "final notice", "confirm your", "click here", "act immediately", "expire",
]
GENERIC_GREETINGS = ["dear customer", "dear user", "dear valued customer", "dear member"]


def _get_model():
    global _model
    if _model is None:
        _model = joblib.load(_MODEL_PATH)
    return _model


def evaluate_content(body: str) -> tuple:
    """Returns (score_out_of_25, list_of_reason_strings)."""
    if not body.strip():
        return 0, []

    score = 0
    reasons = []
    body_lower = body.lower()

    # 1) ML classifier probability of being phishing language (worth up to 15 pts)
    model = _get_model()
    proba = model.predict_proba([body])[0]
    phishing_proba = proba[1]  # class 1 = phishing
    ml_points = round(phishing_proba * 15)
    score += ml_points
    if phishing_proba >= 0.6:
        reasons.append(f"Content classifier scored this message {phishing_proba * 100:.0f}% likely phishing language")

    # 2) Urgency / credential-harvesting keywords (worth up to 6 pts)
    hits = [w for w in URGENCY_WORDS if w in body_lower]
    if hits:
        score += min(6, 2 * len(hits))
        reasons.append(f"Urgency / credential-harvesting language detected ({', '.join(hits[:3])})")

    # 3) Generic salutation (worth 4 pts)
    if any(g in body_lower for g in GENERIC_GREETINGS):
        score += 4
        reasons.append("Generic greeting used instead of the recipient's name")

    return min(score, WEIGHT), reasons
