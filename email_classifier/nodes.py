"""
Part 2 -- Function Nodes
========================

In LangGraph, a **node** is a regular Python function that:
  - Takes the current state as input
  - Returns a dict with the state keys it wants to UPDATE

The returned dict is merged into the state automatically.
You do NOT need to return the entire state -- only the keys that changed.

Nodes 1 and 2 are already implemented as examples.
TODO: implement nodes 3 and 4.
"""

from email_classifier.mock_data import (
    check_urls_against_blocklist,
    analyze_content_keywords,
)


# ---------- Node 1: check_urls (provided) ----------

def check_urls(state: dict) -> dict:
    """Check the email's URLs against the blocklist."""
    result = check_urls_against_blocklist(state["urls"])
    output = {"url_check_result": result}
    if not result["safe"]:
        output["threat_level"] = "dangerous"
    return output


# ---------- Node 2: analyze_content (provided) ----------

def analyze_content(state: dict) -> dict:
    """Analyze the email content for spam/phishing keywords."""
    result = analyze_content_keywords(state["subject"], state["body"])
    return {"content_analysis": result}


# ---------- Node 3: classify_email ----------

def classify_email(state: dict) -> dict:
    """Determine the threat level based on previous analysis results.

    Logic:
        - If url_check_result["safe"] is False  -->  threat_level = "dangerous"
        - Elif content_analysis["is_suspicious"] is True  -->  threat_level = "suspicious"
        - Else  -->  threat_level = "safe"

    Return {"threat_level": <the level you chose>}.
    """
    # TODO: implement (~ 5 lines)
    ...


# ---------- Node 4: generate_response ----------

def generate_response(state: dict) -> dict:
    """Generate a response message based on the threat level.

    Logic:
        - "dangerous"   -->  "ALERT: This email is dangerous. Do not interact with it."
        - "suspicious"  -->  "WARNING: This email looks suspicious. Proceed with caution."
        - "safe"        -->  "This email appears safe. No threats detected."

    Return {"response": <the message>}.
    """
    # TODO: implement (~ 5 lines)
    ...
