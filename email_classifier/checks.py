"""
Verification helpers for the notebook.
Please don't modify this file.
"""

import importlib


def check_part1():
    """Verify the EmailState has the three TODO fields."""
    import email_classifier.state
    importlib.reload(email_classifier.state)
    from email_classifier.state import EmailState

    state = EmailState()

    assert hasattr(state, "email_id"), "Missing field: email_id"
    assert isinstance(state.email_id, str), "email_id should be a str"

    assert hasattr(state, "has_attachments"), "Missing field: has_attachments"
    assert isinstance(state.has_attachments, bool), "has_attachments should be a bool"

    assert hasattr(state, "content_analysis"), "Missing field: content_analysis"
    assert state.content_analysis is None, "content_analysis should default to None"

    test = EmailState(email_id="test_001", has_attachments=True, content_analysis={"score": 0.5})
    assert test.email_id == "test_001"
    assert test.has_attachments is True
    assert test.content_analysis == {"score": 0.5}

    print(f"Fields: {list(EmailState.model_fields.keys())}")
    print("\n=== Part 1 PASSED ===")


def check_classify_email():
    """Verify classify_email returns correct threat levels."""
    import email_classifier.nodes
    importlib.reload(email_classifier.nodes)
    from email_classifier.nodes import classify_email

    result_d = classify_email({
        "url_check_result": {"safe": False, "flagged_urls": ["x"]},
        "content_analysis": {"is_suspicious": False},
    })
    assert result_d["threat_level"] == "dangerous", f"Expected 'dangerous', got '{result_d['threat_level']}'"

    result_s = classify_email({
        "url_check_result": {"safe": True, "flagged_urls": []},
        "content_analysis": {"is_suspicious": True},
    })
    assert result_s["threat_level"] == "suspicious", f"Expected 'suspicious', got '{result_s['threat_level']}'"

    result_ok = classify_email({
        "url_check_result": {"safe": True, "flagged_urls": []},
        "content_analysis": {"is_suspicious": False},
    })
    assert result_ok["threat_level"] == "safe", f"Expected 'safe', got '{result_ok['threat_level']}'"

    print("=== classify_email PASSED ===")


def check_generate_response():
    """Verify generate_response returns a non-empty string for each level."""
    import email_classifier.nodes
    importlib.reload(email_classifier.nodes)
    from email_classifier.nodes import generate_response

    for level in ["dangerous", "suspicious", "safe"]:
        result = generate_response({"threat_level": level})
        assert isinstance(result, dict), "generate_response must return a dict"
        assert "response" in result, "Must return key 'response'"
        assert isinstance(result["response"], str) and len(result["response"]) > 0, (
            f"Response for '{level}' must be a non-empty string"
        )
        print(f"  {level:>12s} -> {result['response']}")

    print("\n=== generate_response PASSED ===")


def check_graph_build():
    """Verify the graph compiles."""
    import email_classifier.graph
    importlib.reload(email_classifier.graph)
    from email_classifier.graph import build_email_classifier

    graph = build_email_classifier()
    assert graph is not None, "build_email_classifier() must return a compiled graph"
    print("Graph compiled successfully!")
    print("\n=== Graph build PASSED ===")
    return graph


def check_graph_results(graph):
    """Run the graph on all mock emails and verify threat levels."""
    from email_classifier.mock_data import MOCK_EMAILS, EXPECTED_THREAT_LEVELS

    print("Running email classifier on mock emails...\n")

    all_passed = True
    for email in MOCK_EMAILS:
        result = graph.invoke(email)
        expected = EXPECTED_THREAT_LEVELS[email["email_id"]]
        actual = result.get("threat_level", "<missing>")
        status = "PASS" if actual == expected else "FAIL"
        if actual != expected:
            all_passed = False
        print(f"  [{status}] {email['email_id']}: expected={expected}, got={actual}")
        print(f"         Response: {result.get('response', '<missing>')}")
        print()

    assert all_passed, "Some emails got the wrong threat level -- check your logic!"
    print("=== Part 3 PASSED ===")


def check_hitl_build():
    """Verify the HITL graph compiles."""
    import email_classifier.hitl
    importlib.reload(email_classifier.hitl)
    from email_classifier.hitl import build_hitl_graph

    hitl_graph = build_hitl_graph()
    assert hitl_graph is not None, "build_hitl_graph() must return a compiled graph"
    print("HITL graph compiled successfully!")
    print("\n=== HITL graph build PASSED ===")
    return hitl_graph


def check_hitl_safe(hitl_graph):
    """Verify a safe email goes through without interrupt."""
    from email_classifier.mock_data import MOCK_EMAILS

    safe_email = MOCK_EMAILS[0]
    config = {"configurable": {"thread_id": "test-safe"}}

    result = hitl_graph.invoke(safe_email, config)
    assert result["threat_level"] == "safe", f"Expected 'safe', got '{result['threat_level']}'"
    assert "response" in result and len(result["response"]) > 0

    print(f"Threat level: {result['threat_level']}")
    print(f"Response: {result['response']}")
    print("\nSafe email went straight through (no interrupt).")
    print("\n=== Safe email PASSED ===")


def check_hitl_interrupt(hitl_graph):
    """Send a suspicious email and verify the graph pauses. Returns config for resume."""
    from email_classifier.mock_data import MOCK_EMAILS

    suspicious_email = MOCK_EMAILS[2]
    config = {"configurable": {"thread_id": "test-suspicious"}}

    state_before = hitl_graph.invoke(suspicious_email, config)

    print("=" * 50)
    print("GRAPH PAUSED -- waiting for human review")
    print("=" * 50)
    print(f"  Subject:      {state_before.get('subject', '<not set>')}")
    print(f"  Sender:       {state_before.get('sender', '<not set>')}")
    print(f"  Threat level: {state_before.get('threat_level', '<not set>')}")
    print(f"  Spam keywords found: {state_before.get('content_analysis', {}).get('matched_keywords', [])}")
    print()

    snapshot = hitl_graph.get_state(config)
    assert snapshot.next, "Graph should be paused with a 'next' node pending"
    print(f"Next node waiting: {snapshot.next}")
    print("\n=== Interrupt PASSED ===")

    return config
