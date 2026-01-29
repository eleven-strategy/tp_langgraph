"""
Part 2 -- Function Nodes
========================

In LangGraph, a **node** is a regular Python function that:
  - Takes the current state as input
  - Returns a dict with the state keys it wants to UPDATE

The returned dict is merged into the state automatically.
You do NOT need to return the entire state -- only the keys that changed.

Node 1 is already implemented as an example.
TODO: implement nodes 2 and 3.
"""

from email_classifier.state import EmailState
from email_classifier.mock_data import (
    check_urls_against_blocklist,
    analyze_content_keywords,
)


# ---------- Node 1: check_urls (provided) ----------

def check_urls(state: EmailState) -> dict:
    """Check the email's URLs against the blocklist."""
    result = check_urls_against_blocklist(state.urls)
    output = {"url_check_result": result}
    if not result["safe"]:
        output["threat_level"] = "dangerous"
    return output


# ---------- Node 2: analyze_content ----------

def analyze_content(state: EmailState) -> dict:
    """Analyze the email content and determine the threat level.

    This node only runs when URLs are safe (dangerous emails are
    already handled by the graph routing).

    Steps:
        1. Call analyze_content_keywords(state.subject, state.body)
           to get the analysis result.
        2. Set the threat level based on the result:
           - If result["is_suspicious"] is True  -->  threat_level = "suspicious"
           - Else                                 -->  threat_level = "safe"

    Return {"content_analysis": result, "threat_level": <the level you chose>}.

    Hint: look at check_urls above for a similar pattern.
    """
    # TODO: implement (~ 4 lines)
    ...


# ---------- Node 3: generate_response ----------

def generate_response(state: EmailState) -> dict:
    """Generate a response message based on the threat level.

    Logic:
        - "dangerous"   -->  "ALERT: This email is dangerous. Do not interact with it."
        - "suspicious"  -->  "WARNING: This email looks suspicious. Proceed with caution."
        - "safe"        -->  "This email appears safe. No threats detected."

    Return {"response": <the message>}.

    Hint: read state.threat_level
    """
    # TODO: implement (~ 5 lines)
    ...
