"""
Part 4 -- Human-in-the-Loop
===========================

Sometimes an automated pipeline should pause and let a human make the call.
LangGraph supports this with **interrupt_before** (or interrupt_after).

When the graph reaches a node listed in interrupt_before, it:
  1. Saves its current state to the **checkpointer**
  2. Stops execution and returns the state so far
  3. Waits for you to update the state and **resume**

In this part you will:
  - Add a "human_review" node that acts as a pause point
  - Build a graph that interrupts before human_review for suspicious emails
  - Use a MemorySaver checkpointer to persist state between runs

The routing logic:
  - "dangerous"  --> generate_response  (no human needed, clearly bad)
  - "suspicious" --> human_review       (human decides)
  - "safe"       --> generate_response  (no human needed, clearly fine)
"""

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from email_classifier.state import EmailState
from email_classifier.nodes import (
    check_urls,
    analyze_content,
    classify_email,
    generate_response,
)


# ---------- Human review node (provided) ----------

def human_review(state: dict) -> dict:
    """Placeholder node where a human can inspect and override the threat_level.

    This node does nothing by itself -- the magic happens because the graph
    INTERRUPTS before reaching it, giving the human a chance to update
    the state (e.g. change threat_level from "suspicious" to "safe").
    After the human updates the state, the graph resumes from this node.
    """
    # Nothing to change -- just pass through
    return {}


# ---------- Routing function ----------

def route_after_classify(state: dict) -> str:
    """Route based on threat_level after classification.

    Logic:
        - "dangerous"  --> "generate_response"
        - "suspicious" --> "human_review"
        - "safe"       --> "generate_response"

    Returns:
        The name of the next node.
    """
    # TODO: implement (~ 3 lines)
    ...


# ---------- Graph builder ----------

def build_hitl_graph():
    """Build the email classifier graph WITH human-in-the-loop.

    The graph:

        check_urls -> analyze_content -> classify_email --?--> human_review --> generate_response -> END
                                                         |                            ^
                                                         +-- (safe / dangerous) ------+

    Steps:
        1. Create a StateGraph using EmailState.
        2. Add five nodes:
              "check_urls", "analyze_content", "classify_email",
              "human_review", "generate_response"
        3. Set entry point to "check_urls".
        4. Add edges:
              check_urls -> analyze_content -> classify_email
        5. Add conditional edges from "classify_email"
           using route_after_classify:
              "generate_response" -> "generate_response"
              "human_review"      -> "human_review"
        6. Add edge: "human_review" -> "generate_response"
        7. Add edge: "generate_response" -> END
        8. Create a MemorySaver checkpointer.
        9. Compile with:
              - checkpointer=<your checkpointer>
              - interrupt_before=["human_review"]
        10. Return the compiled graph.
    """
    # TODO: implement (~ 12 lines)
    ...
