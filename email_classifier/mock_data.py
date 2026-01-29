"""
Mock data and helper functions for the Email Classifier.

This module provides:
- Sample emails to test the pipeline
- A URL blocklist checker
- A keyword-based content analyzer

Please don't modify this file.
"""

# ---------------------------------------------------------------------------
# Mock emails
# ---------------------------------------------------------------------------

MOCK_EMAILS = [
    {
        "email_id": "email_001",
        "subject": "Team meeting notes - January 2026",
        "body": (
            "Hi everyone,\n\n"
            "Please find attached the notes from our last team meeting. "
            "Next meeting is scheduled for Friday at 2 PM in room B12.\n\n"
            "Best regards,\nAlice"
        ),
        "sender": "alice.martin@company.com",
        "urls": [],
        "has_attachments": True,
    },
    {
        "email_id": "email_002",
        "subject": "URGENT - Your account has been compromised",
        "body": (
            "Dear user,\n\n"
            "We detected suspicious activity on your account. "
            "Click immediately on the link below to verify your identity "
            "and reset your password before your account is suspended.\n\n"
            "Verify now: https://secure-login.malware-site.com/verify\n\n"
            "If you do not act within 24 hours, your account will be permanently deleted.\n\n"
            "Security Team"
        ),
        "sender": "security@random-domain.net",
        "urls": ["https://secure-login.malware-site.com/verify"],
        "has_attachments": False,
    },
    {
        "email_id": "email_003",
        "subject": "URGENT: Invoice #4521 - Payment required",
        "body": (
            "Hello,\n\n"
            "Please find your invoice attached. Act now -- payment is overdue.\n"
            "This offer expires in 7 days or your service will be interrupted.\n"
            "You can view the invoice online at: https://invoices.legitimate-service.com/4521\n\n"
            "Thank you.\n"
            "Accounting Department"
        ),
        "sender": "billing@unknown-sender.org",
        "urls": ["https://invoices.legitimate-service.com/4521"],
        "has_attachments": True,
    },
    {
        "email_id": "email_004",
        "subject": "Congratulations! You won a free iPhone!",
        "body": (
            "CONGRATULATIONS!!!\n\n"
            "You have been selected as the winner of our monthly draw! "
            "Click the link below to claim your FREE iPhone 17 Pro Max!\n\n"
            "Claim your prize: https://free-prizes.phishing-page.net/claim\n\n"
            "Act now! This offer expires in 1 hour! "
            "Send your credit card details to confirm your identity.\n\n"
            "Regards,\nPrize Committee"
        ),
        "sender": "prizes@phishing-page.net",
        "urls": ["https://free-prizes.phishing-page.net/claim"],
        "has_attachments": False,
    },
]

# Expected threat levels (used by the verification notebook)
EXPECTED_THREAT_LEVELS = {
    "email_001": "safe",
    "email_002": "dangerous",
    "email_003": "suspicious",
    "email_004": "dangerous",
}

# ---------------------------------------------------------------------------
# URL blocklist
# ---------------------------------------------------------------------------

URL_BLOCKLIST = {
    "malware-site.com",
    "phishing-page.net",
    "evil-download.org",
    "fake-bank-login.com",
    "credential-harvest.net",
}


def check_urls_against_blocklist(urls: list[str]) -> dict:
    """Check a list of URLs against the known-bad domain blocklist.

    Args:
        urls: List of URL strings to check.

    Returns:
        dict with keys:
            - "safe" (bool): True if ALL urls are safe
            - "flagged_urls" (list[str]): URLs whose domain is in the blocklist
            - "checked_count" (int): Total URLs checked
    """
    flagged = []
    for url in urls:
        # Extract domain from URL (simple approach)
        domain = url.split("//")[-1].split("/")[0].split(":")[0]
        # Check domain and parent domains
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in URL_BLOCKLIST:
                flagged.append(url)
                break

    return {
        "safe": len(flagged) == 0,
        "flagged_urls": flagged,
        "checked_count": len(urls),
    }


# ---------------------------------------------------------------------------
# Content analysis keywords
# ---------------------------------------------------------------------------

SPAM_KEYWORDS = [
    "urgent",
    "click immediately",
    "act now",
    "verify your identity",
    "reset your password",
    "account suspended",
    "account will be deleted",
    "free iphone",
    "you won",
    "congratulations",
    "credit card details",
    "claim your prize",
    "expires in",
    "send your password",
]


def analyze_content_keywords(subject: str, body: str) -> dict:
    """Analyze email subject and body for spam/phishing keyword indicators.

    Args:
        subject: Email subject line.
        body: Email body text.

    Returns:
        dict with keys:
            - "spam_score" (float): 0.0 to 1.0, proportion of keywords matched
            - "matched_keywords" (list[str]): Which keywords were found
            - "is_suspicious" (bool): True if spam_score >= 0.15
    """
    text = (subject + " " + body).lower()
    matched = [kw for kw in SPAM_KEYWORDS if kw.lower() in text]

    score = len(matched) / len(SPAM_KEYWORDS) if SPAM_KEYWORDS else 0.0

    return {
        "spam_score": round(score, 3),
        "matched_keywords": matched,
        "is_suspicious": score >= 0.15,
    }
