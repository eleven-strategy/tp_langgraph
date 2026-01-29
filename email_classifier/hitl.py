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
  - Use an InMemorySaver checkpointer to persist state between runs

The routing logic (after analyze_content):
  - "suspicious" --> human_review       (human decides)
  - "safe"       --> generate_response  (no human needed)

Note: dangerous emails never reach analyze_content -- they are routed
directly to generate_response after check_urls (same as in Part 3).
"""

from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import InMemorySaver

from email_classifier.state import EmailState
from email_classifier.nodes import (
    check_urls,
    analyze_content,
    generate_response,
)


# ---------- Human review node (provided) ----------

def human_review(state: EmailState) -> dict:
    """Placeholder node where a human can inspect and override the threat_level.

    This node does nothing by itself -- the magic happens because the graph
    INTERRUPTS before reaching it, giving the human a chance to update
    the state (e.g. change threat_level from "suspicious" to "safe").
    After the human updates the state, the graph resumes from this node.
    """
    return {}


# ---------- Routing functions ----------

def route_after_urls(state: EmailState) -> str:
    """Route based on URL check results (same logic as Part 3).

    - Malicious URLs  --> "generate_response"  (skip analysis, already dangerous)
    - Safe URLs       --> "analyze_content"    (continue pipeline)
    """
    if state.url_check_result and not state.url_check_result["safe"]:
        return "generate_response"
    return "analyze_content"


def route_after_analysis(state: EmailState) -> str:
    """Route based on threat_level after content analysis.

    Logic:
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

        check_urls ──?──> analyze_content ──?──> human_review ──> generate_response ──> END
                     │                       │                            ▲
                     │                       └── (safe) ─────────────────┘
                     └── (malicious URLs) ──────────────────────────────┘

    Steps:
        1. Create a StateGraph using EmailState.
        2. Add four nodes:
              "check_urls", "analyze_content",
              "human_review", "generate_response"
        3. Add edges:
              START -> check_urls
        4. Add conditional edges from "check_urls"
           using route_after_urls:
              "analyze_content"   -> "analyze_content"
              "generate_response" -> "generate_response"
        5. Add conditional edges from "analyze_content"
           using route_after_analysis:
              "human_review"      -> "human_review"
              "generate_response" -> "generate_response"
        6. Add edge: "human_review" -> "generate_response"
        7. Add edge: "generate_response" -> END
        8. Create an InMemorySaver checkpointer.
        9. Compile with:
              - checkpointer=<your checkpointer>
              - interrupt_before=["human_review"]
       10. Return the compiled graph.
    """
    # TODO: implement (~ 18 lines)
    ...
