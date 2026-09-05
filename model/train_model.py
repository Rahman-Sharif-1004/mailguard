"""
Trains the MailGuard content classifier (Section 21 of the report):
TfidfVectorizer + MultinomialNB, exactly as described.

Run this once:  python model/train_model.py
It saves classifier.joblib in the same folder, which app.py loads at runtime.

NOTE: The dataset below is a small illustrative sample so the prototype
can be trained and demonstrated instantly. For production use, replace
this with the larger, properly labelled dataset described in Section 22
of the report (940 training / 235 testing emails).
"""

from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
import joblib
import os

# ---- Genuine email samples ----
genuine = [
    "Hi team, attaching the meeting notes from today's sync. Let me know if I missed anything.",
    "Your order #48213 has shipped and will arrive within 3-5 business days. Track it here.",
    "Thanks for subscribing to our newsletter. Here are this week's top stories.",
    "Reminder: your dentist appointment is scheduled for Tuesday at 10 AM.",
    "The quarterly report is ready for review. Please share your comments by Friday.",
    "Welcome to the team! Here's your onboarding checklist and first-week schedule.",
    "Your monthly statement is now available in your account dashboard.",
    "Congratulations on completing the course! Your certificate is attached.",
    "Here's the agenda for tomorrow's product review meeting.",
    "Your flight booking is confirmed. Check-in opens 24 hours before departure.",
    "The library book you reserved is ready for pickup at the front desk.",
    "Thank you for your purchase. Your receipt is attached for your records.",
    "Please find attached the invoice for last month's consulting work.",
    "Our office will be closed on Monday for the public holiday.",
    "Your gym membership renews automatically next week, no action needed.",
    "Here is the recording of yesterday's webinar in case you missed it.",
    "The project deadline has been moved to next Friday, please adjust your plan.",
    "Your password was changed successfully. If this wasn't you, contact support.",
    "New comment on your post: 'Great write-up, thanks for sharing!'",
    "Your subscription renewal receipt for this month is attached.",
]

# ---- Phishing email samples ----
phishing = [
    "URGENT: Your account has been suspended. Verify your identity immediately or lose access.",
    "Congratulations! You have won a $1000 gift card. Click here to claim your prize now.",
    "Your account will be permanently closed in 24 hours unless you confirm your password.",
    "Security Alert: unusual login detected. Verify your account now to avoid suspension.",
    "Dear Customer, your payment failed. Update your billing details immediately to avoid service loss.",
    "Act now! Your invoice is overdue and legal action will be taken if not paid today.",
    "You have a pending refund of $499. Confirm your bank details to receive it now.",
    "Final notice: your mailbox storage is full, click here to verify and avoid deletion.",
    "Your package could not be delivered. Pay a small customs fee now to release it.",
    "We detected suspicious activity on your account. Verify immediately to restore access.",
    "Claim your inheritance of $2,000,000 by replying with your bank account details.",
    "Your subscription payment was declined, update your card now or lose your account.",
    "Immediate action required: confirm your identity within 12 hours or your account will be deleted.",
    "You've been selected for a special reward. Verify your details to unlock your prize.",
    "Dear User, unusual activity detected, click the link below to secure your account now.",
    "Your document is waiting for signature. Click here immediately to review and sign.",
    "Warning: your email storage exceeded quota, verify now to avoid permanent suspension.",
    "Your account access will expire today, click here to renew and confirm your password.",
    "We could not verify your recent payment, confirm your card details within 24 hours.",
    "Urgent security update required, verify your credentials now to keep your account active.",
]

X_train = genuine + phishing
y_train = ([0] * len(genuine)) + ([1] * len(phishing))  # 0 = genuine, 1 = phishing

model = Pipeline([
    ('tfidf', TfidfVectorizer(stop_words='english', max_features=5000)),
    ('clf', MultinomialNB()),
])
model.fit(X_train, y_train)

out_path = os.path.join(os.path.dirname(__file__), 'classifier.joblib')
joblib.dump(model, out_path)
print(f"Model trained on {len(X_train)} samples and saved to {out_path}")
